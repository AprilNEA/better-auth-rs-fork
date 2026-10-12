use better_auth_core::{AuthError, AuthResult, SchemaValue};
use serde_json::Value;

use super::{OAuthProvider, OAuthUserInfo, OAuthUserInfoRequest, OAuthUserInfoResponse};
use crate::plugins::oauth::google::AcceptedIdToken;
use crate::plugins::oauth::social_profile::{ProviderProfile, fetch_http_profile};

impl OAuthProvider {
    /// Configure PayPal sandbox code login with PKCE and HTTP Basic grants.
    /// Optional ID tokens require an explicit application `verify_id_token` callback.
    pub fn paypal(client_id: &str, client_secret: &str) -> Self {
        Self {
            kind: super::ProviderKind::PayPal,
            user_info_url: Some(
                "https://api-m.sandbox.paypal.com/v1/identity/oauth2/userinfo".into(),
            ),
            ..Self::custom(
                client_id,
                client_secret,
                "https://www.sandbox.paypal.com/signin/authorize",
                "https://api-m.sandbox.paypal.com/v1/oauth2/token",
            )
        }
    }

    /// Configure PayPal live code login with the same explicit ID-token verification policy.
    pub fn paypal_live(client_id: &str, client_secret: &str) -> Self {
        Self {
            auth_url: "https://www.paypal.com/signin/authorize".into(),
            token_url: "https://api-m.paypal.com/v1/oauth2/token".into(),
            user_info_url: Some("https://api-m.paypal.com/v1/identity/oauth2/userinfo".into()),
            ..Self::paypal(client_id, client_secret)
        }
    }

    pub(in crate::plugins::oauth) fn is_paypal(&self) -> bool {
        matches!(self.kind, super::ProviderKind::PayPal)
    }
}

pub(super) fn decode_profile(profile: Value) -> Result<OAuthUserInfo, String> {
    Ok(OAuthUserInfo {
        id: profile
            .get("user_id")
            .and_then(Value::as_str)
            .ok_or("Missing PayPal user_id")?
            .into(),
        name: profile
            .get("name")
            .cloned()
            .map(serde_json::from_value::<Option<String>>)
            .transpose()
            .map_err(|error| format!("Invalid PayPal name: {error}"))?
            .map(Into::into)
            .unwrap_or_default(),
        email: super::defaults::profile_email(&profile)?,
        image: profile
            .get("picture")
            .cloned()
            .map(serde_json::from_value)
            .transpose()
            .map_err(|error| format!("Invalid PayPal picture: {error}"))?,
        email_verified: SchemaValue::from_json(profile.get("email_verified").cloned())
            .map_err(|error| error.to_string())?,
        additional_fields: Default::default(),
    })
}

pub(in crate::plugins::oauth) async fn fetch_user_info(
    provider: &OAuthProvider,
    request: OAuthUserInfoRequest,
    expected_nonce: Option<&str>,
    claims: Option<Value>,
) -> AuthResult<ProviderProfile> {
    let logger = better_auth_core::observability::logger::current();
    if !request.access_token.is_truthy()? {
        logger.error("Access token is required to fetch PayPal user info", &[])?;
        return Ok(ProviderProfile::default());
    }
    let result: AuthResult<ProviderProfile> = async {
        let url = provider
            .user_info_url
            .as_deref()
            .ok_or_else(|| AuthError::internal("Missing PayPal user_info_url"))?;
        let profile = fetch_http_profile(
            provider
                .user_info_request(url, &request.access_token.field_value())?
                .query(&[("schema", "paypalv1.1")]),
        )
        .await?;
        let Some(profile) = profile.filter(|profile| !profile.is_null()) else {
            logger.error("Failed to fetch user info from PayPal", &[])?;
            return Ok(ProviderProfile::default());
        };
        if request.id_token.is_truthy()? {
            let claims = match claims {
                Some(claims) => claims,
                None => {
                    let token = request.id_token.field_value();
                    let token = crate::plugins::oauth::providers::jwt_string(&token)?;
                    let verifier = provider.verify_id_token.as_deref().ok_or_else(|| {
                        AuthError::internal(
                            "PayPal ID token requires an explicit application verifier",
                        )
                    })?;
                    AcceptedIdToken::verify(verifier, &token, expected_nonce, None)
                        .await
                        .ok_or_else(crate::plugins::oauth::id_token::invalid)?
                        .value()?
                }
            };
            let subject = claims
                .get("sub")
                .and_then(Value::as_str)
                .filter(|subject| !subject.is_empty());
            let profile_subject = profile
                .get("sub")
                .filter(|value| !value.is_null())
                .or_else(|| profile.get("user_id"))
                .and_then(Value::as_str);
            if subject.is_none() || subject != profile_subject {
                logger.error(
                    "PayPal user info subject does not match ID token subject",
                    &[],
                )?;
                return Ok(ProviderProfile::default());
            }
        }
        let Some(user) = provider.decode_profile(profile.clone())? else {
            return Ok(ProviderProfile::default());
        };
        let response = OAuthUserInfoResponse {
            user,
            data: profile,
        };
        ProviderProfile::from_typed(provider, response)?
            .map_user(provider)
            .await
    }
    .await;
    match result {
        Ok(response) => Ok(response),
        Err(error) => {
            logger.error(
                "Failed to fetch user info from PayPal:",
                &[better_auth_core::observability::LogArgument::Error(&error)],
            )?;
            Ok(ProviderProfile::default())
        }
    }
}

pub(in crate::plugins::oauth) fn token_result(
    result: AuthResult<super::OAuthTokenSet>,
    grant: crate::plugins::oauth::token::TokenGrantType,
) -> AuthResult<super::OAuthTokenSet> {
    use crate::plugins::oauth::token::TokenGrantType;
    result.or_else(|error| {
        let (message, code) = match grant {
            TokenGrantType::AuthorizationCode => (
                "PayPal token exchange failed:",
                "FAILED_TO_GET_ACCESS_TOKEN",
            ),
            TokenGrantType::RefreshToken => (
                "PayPal token refresh failed:",
                "FAILED_TO_REFRESH_ACCESS_TOKEN",
            ),
        };
        better_auth_core::observability::logger::current().error(
            message,
            &[better_auth_core::observability::LogArgument::Error(&error)],
        )?;
        Err(AuthError::internal(code))
    })
}

#[cfg(test)]
#[expect(
    clippy::panic_in_result_fn,
    reason = "The token failure contract asserts logger arguments and the resulting error identity."
)]
mod tests {
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };

    use better_auth_core::{
        AuthConfig, AuthContext, FieldMap, FieldValue,
        observability::{LogArgument, LogLevel, LogSink, LoggerConfig},
        store::{EphemeralStore, StatelessSchema},
    };

    use super::*;
    use crate::plugins::oauth::token::TokenGrantType;

    struct TokenFailureLog {
        calls: AtomicUsize,
        original: FieldValue,
        failure: Option<FieldValue>,
        message: &'static str,
    }

    impl LogSink for TokenFailureLog {
        fn log(
            &self,
            level: LogLevel,
            message: LogArgument<'_>,
            arguments: &[LogArgument<'_>],
        ) -> AuthResult<()> {
            let _ = self.calls.fetch_add(1, Ordering::SeqCst);
            assert_eq!(level, LogLevel::Error);
            assert_eq!(message.to_string(), self.message);
            assert_eq!(arguments.len(), 1);
            let argument = match arguments.first() {
                Some(LogArgument::Error(error)) => error.downcast_ref::<AuthError>(),
                _ => None,
            };
            assert!(
                argument
                    .and_then(AuthError::raw_value)
                    .is_some_and(|value| value.strict_equals(&self.original))
            );
            match &self.failure {
                Some(value) => Err(AuthError::from_thrown(value.clone())),
                None => Ok(()),
            }
        }
    }

    #[tokio::test]
    async fn token_failure_logs_before_replacing_error_and_preserves_logger_failure()
    -> AuthResult<()> {
        for (grant, message, code) in [
            (
                TokenGrantType::AuthorizationCode,
                "PayPal token exchange failed:",
                "FAILED_TO_GET_ACCESS_TOKEN",
            ),
            (
                TokenGrantType::RefreshToken,
                "PayPal token refresh failed:",
                "FAILED_TO_REFRESH_ACCESS_TOKEN",
            ),
        ] {
            for throw in [false, true] {
                let original: FieldValue =
                    FieldMap::from([("failure".into(), "token".into())]).into();
                let failure: FieldValue =
                    FieldMap::from([("failure".into(), "logger".into())]).into();
                let sink = Arc::new(TokenFailureLog {
                    calls: AtomicUsize::new(0),
                    original: original.clone(),
                    failure: throw.then(|| failure.clone()),
                    message,
                });
                let mut config =
                    AuthConfig::new("paypal-logger-contract-secret-at-least-32-characters")
                        .base_url("http://paypal-logger.test");
                config.logger = LoggerConfig {
                    log: Some(sink.clone()),
                    ..Default::default()
                }
                .into();
                let config = Arc::new(config);
                let database = Arc::new(EphemeralStore::new(config.clone()));
                let context = AuthContext::<StatelessSchema>::new(config, database)?;
                let result = context
                    .with_native_context(Default::default(), |_| async move {
                        token_result(Err(AuthError::from_thrown(original)), grant)
                    })
                    .await;
                let Err(error) = result else {
                    return Err(AuthError::internal(
                        "PayPal token failure unexpectedly succeeded",
                    ));
                };
                assert_eq!(sink.calls.load(Ordering::SeqCst), 1);
                if throw {
                    assert!(
                        error
                            .raw_value()
                            .is_some_and(|value| value.strict_equals(&failure))
                    );
                } else {
                    assert!(matches!(error, AuthError::Internal(message) if message == code));
                }
            }
        }
        Ok(())
    }
}
