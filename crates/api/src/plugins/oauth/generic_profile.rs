use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use better_auth_core::{AuthError, AuthResult, FieldMap, FieldValue, Utf16String};
use serde_json::{Map, Value};

use super::generic::GenericOAuthProfileContext;
use super::providers::{OAuthTokenSet, OAuthUserInfoRequest};
use super::resolved::ResolvedGenericOAuth;

#[cfg(test)]
tokio::task_local! {
    pub(super) static PROFILE_OBSERVER: std::sync::Arc<dyn Fn(&FieldValue) + Send + Sync>;
}

#[cfg(test)]
fn observe_profile(value: &FieldValue) {
    let _ = PROFILE_OBSERVER.try_with(|observe| observe(value));
}

#[derive(Debug, thiserror::Error)]
pub(super) enum GenericProfileError {
    #[error(transparent)]
    Profile(#[from] AuthError),
    #[error(transparent)]
    Identity(AuthError),
}

impl GenericProfileError {
    pub(super) fn into_auth_error(self) -> AuthError {
        match self {
            Self::Profile(error) => error,
            Self::Identity(_) => super::social_profile::missing_profile(),
        }
    }
}

pub(super) async fn resolve_account_subject(
    provider: &ResolvedGenericOAuth,
    subject_tokens: &OAuthTokenSet,
    profile: &FieldValue,
) -> AuthResult<FieldValue> {
    let subject = if let Some(resolver) = &provider.config.account_subject {
        let subject_tokens = OAuthUserInfoRequest::from_fields(subject_tokens.fields());
        resolver
            .resolve_subject_native(&subject_tokens, profile)
            .await?
    } else {
        let field = if provider.is_oidc { "sub" } else { "id" };
        let subject = profile.model_property(field)?;
        if subject.is_null() || subject.is_undefined() {
            FieldValue::from("")
        } else {
            subject
        }
    };
    account_subject_string(subject)
}

pub(super) fn account_subject_string(subject: FieldValue) -> AuthResult<FieldValue> {
    let account_id = subject.display_utf16()?;
    let empty = account_id.as_utf16().iter().all(|unit| {
        char::from_u32(u32::from(*unit))
            .is_some_and(crate::plugins::helpers::oauth_scope_whitespace)
    });
    if matches!(subject, FieldValue::Number(number) if !number.is_finite())
        || empty
        || account_id == Utf16String::from("undefined")
        || account_id == Utf16String::from("null")
    {
        return Err(AuthError::internal("OAUTH_ACCOUNT_SUBJECT_INVALID"));
    }
    Ok(account_id.into())
}

pub(super) async fn fetch_profile(
    provider: &ResolvedGenericOAuth,
    tokens: &OAuthUserInfoRequest,
    verified_claims: Option<Value>,
) -> Result<FieldValue, GenericProfileError> {
    let mut fields = tokens.fields();
    let expected_nonce = fields.remove("expectedIdTokenNonce").unwrap_or_default();
    let tokens = OAuthUserInfoRequest::from_fields(fields);
    let verified_claims = if verified_claims.is_some() {
        verified_claims
    } else if tokens.id_token.is_truthy()?
        && let Some(verifier) = &provider.verifier
    {
        let token = tokens.id_token.field_value();
        let token = super::providers::jwt_string(&token).map_err(GenericProfileError::Identity)?;
        Some(
            verifier
                .verify_native_nonce(&token, &expected_nonce)
                .await
                .map_err(|error| {
                    GenericProfileError::Identity(AuthError::internal(format!(
                        "ID token verification failed: {error}"
                    )))
                })?,
        )
    } else {
        None
    };

    let raw = if let Some(handler) = &provider.config.get_user_info {
        handler
            .get_user_info_native(
                &tokens,
                GenericOAuthProfileContext::new(
                    &provider.config,
                    expected_nonce.as_str(),
                    verified_claims.as_ref(),
                ),
            )
            .await?
    } else {
        default_profile(provider, &tokens, verified_claims).await?
    };
    if !raw.is_truthy() {
        #[cfg(test)]
        observe_profile(&FieldValue::Null);
        return Ok(FieldValue::Null);
    }
    let mapped = match &provider.config.map_profile_to_user {
        Some(mapper) => mapper.map_profile_native(&raw).await?,
        None => FieldValue::Undefined,
    };
    let mut user = FieldMap::from([
        ("email".into(), raw.model_property("email")?),
        ("emailVerified".into(), raw.model_property("emailVerified")?),
        ("image".into(), raw.model_property("image")?),
        ("name".into(), raw.model_property("name")?),
    ]);
    user.extend(mapped.enumerable_fields()?);
    if user.get("image").is_some_and(FieldValue::is_null) {
        let _ = user.insert("image".into(), FieldValue::Undefined);
    }
    let response = FieldMap::from([("user".into(), user.into()), ("data".into(), raw)]).into();
    #[cfg(test)]
    observe_profile(&response);
    Ok(response)
}

async fn default_profile(
    provider: &ResolvedGenericOAuth,
    tokens: &OAuthUserInfoRequest,
    verified_claims: Option<Value>,
) -> AuthResult<FieldValue> {
    let claims = verified_claims.or_else(|| {
        super::providers::jwt_string(&tokens.id_token.field_value())
            .ok()
            .and_then(|token| decode_claims(&token))
    });
    if let Some(claims) = claims {
        let claims = FieldValue::from(claims);
        if !claims.is_null()
            && !claims.is_undefined()
            && claims.model_property("sub")?.is_truthy()
            && claims.model_property("email")?.is_truthy()
        {
            let mut profile = FieldMap::from([
                ("id".into(), claims.model_property("sub")?),
                (
                    "emailVerified".into(),
                    claims.model_property("email_verified")?,
                ),
                ("image".into(), claims.model_property("picture")?),
            ]);
            profile.extend(claims.enumerable_fields()?);
            return Ok(profile.into());
        }
    }

    let Some(endpoint) = provider
        .config
        .user_info_url
        .as_deref()
        .filter(|endpoint| !endpoint.is_empty())
    else {
        return Ok(FieldValue::Null);
    };
    let response = reqwest::Client::new()
        .get(endpoint)
        .header(
            reqwest::header::AUTHORIZATION,
            super::providers::token_http::authorization(
                "Bearer",
                &tokens.access_token.field_value(),
            )?,
        )
        .send()
        .await
        .map_err(|error| AuthError::internal(format!("User info request failed: {error}")))?;
    let success = response.status().is_success();
    let body = response
        .text()
        .await
        .map_err(|error| AuthError::internal(format!("User info response failed: {error}")))?;
    if !success || body.is_empty() {
        return Ok(FieldValue::Null);
    }
    let profile: Value = serde_json::from_str(&body)
        .map_err(|error| AuthError::internal(format!("Invalid user info response: {error}")))?;
    let profile = FieldValue::from(profile);
    if !profile.is_truthy() {
        return Ok(FieldValue::Null);
    }
    let mut output = profile.enumerable_fields()?;
    let _ = output.insert("email".into(), profile.model_property("email")?);
    let verified = profile.model_property("email_verified")?;
    let _ = output.insert(
        "emailVerified".into(),
        if verified.is_null() || verified.is_undefined() {
            FieldValue::Bool(false)
        } else {
            verified
        },
    );
    let _ = output.insert("image".into(), profile.model_property("picture")?);
    let _ = output.insert("name".into(), profile.model_property("name")?);
    Ok(output.into())
}

// Generic OAuth without discovery retains upstream's unverified JWT decoding path.
// Providers that require signed ID tokens are rejected during initialization without JWKS.
pub(super) fn decode_claims(token: &str) -> Option<Value> {
    let mut parts = token.split('.');
    let (Some(_), Some(payload), Some(_), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return None;
    };
    let decoded = URL_SAFE_NO_PAD.decode(payload.trim_end_matches('=')).ok()?;
    let claims: Map<String, Value> = serde_json::from_slice(&decoded).ok()?;
    Some(Value::Object(claims))
}

#[cfg(test)]
#[path = "generic_profile_tests.rs"]
mod tests;

#[cfg(all(test, feature = "axum"))]
#[path = "generic_profile_results_tests.rs"]
mod result_tests;
