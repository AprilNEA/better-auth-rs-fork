use better_auth_core::{AuthError, AuthResult, FieldValue};

use super::google;
use super::id_token::VerifiedIdToken;
use super::providers::{OAuthUserInfoRequest, OAuthUserInfoResponse};
use super::resolved::ResolvedProvider;

#[path = "social_profile_native.rs"]
mod native;
pub(super) use native::{LegacySubject, ProviderProfile};

#[path = "social_http.rs"]
mod http;
pub(super) use http::{fetch_http_profile, fetch_native as fetch_native_profile};

pub(super) async fn resolve_account_subject(
    provider: &ResolvedProvider,
    subject_tokens: &FieldValue,
    raw_profile: &FieldValue,
    legacy_subject: Option<&LegacySubject>,
) -> AuthResult<FieldValue> {
    if let Some(generic) = &provider.generic {
        return super::generic_profile::resolve_account_subject(
            generic,
            subject_tokens,
            raw_profile,
        )
        .await;
    }
    let subject = if let Some(resolver) = &provider.config.account_subject {
        resolver
            .resolve_subject_native(subject_tokens, raw_profile)
            .await?
    } else if let Some(subject) = provider.config.builtin_account_subject(raw_profile)? {
        subject
    } else {
        match legacy_subject {
            Some(LegacySubject::Direct(subject)) => subject.clone(),
            Some(LegacySubject::ProfileUser(response)) => {
                response.model_property("user")?.model_property("id")?
            }
            None => FieldValue::Undefined,
        }
    };
    super::generic_profile::account_subject_string(subject)
}

pub(super) async fn fetch_user_info_from_provider(
    provider: &ResolvedProvider,
    request: OAuthUserInfoRequest,
    expected_nonce: Option<&str>,
) -> AuthResult<ProviderProfile> {
    fetch_user_info_with_claims(provider, request, expected_nonce, None).await
}

pub(super) async fn fetch_user_info_with_claims(
    provider: &ResolvedProvider,
    request: OAuthUserInfoRequest,
    expected_nonce: Option<&str>,
    claims: Option<VerifiedIdToken>,
) -> AuthResult<ProviderProfile> {
    if let Some(generic) = &provider.generic {
        let claims = match claims {
            Some(VerifiedIdToken::Generic(claims)) => Some(claims),
            None => None,
            Some(
                VerifiedIdToken::Apple(_)
                | VerifiedIdToken::Google(_)
                | VerifiedIdToken::Cognito(_)
                | VerifiedIdToken::Microsoft(_)
                | VerifiedIdToken::Paybin(_)
                | VerifiedIdToken::PayPal(_)
                | VerifiedIdToken::Facebook(_),
            ) => {
                return Err(AuthError::internal(
                    "Social claims supplied to a Generic provider",
                ));
            }
        };
        return super::generic_profile::fetch_profile(generic, &request, claims)
            .await
            .map(ProviderProfile::from)
            .map_err(super::generic_profile::GenericProfileError::into_auth_error);
    }
    if let Some(handler) = &provider.config.get_user_info {
        let value = handler.get_user_info_native(request).await?;
        let legacy_subject = (provider.config.is_custom()
            && provider.config.account_subject.is_none())
        .then(|| LegacySubject::ProfileUser(value.clone()));
        let response = ProviderProfile {
            value,
            legacy_subject,
        };
        return Ok(response);
    }
    if let Some(options) = provider.config.microsoft_options() {
        let claims = match claims {
            Some(VerifiedIdToken::Microsoft(claims)) => Some(claims),
            None => None,
            Some(_) => {
                return Err(AuthError::internal(
                    "Non-Microsoft claims supplied to Microsoft",
                ));
            }
        };
        return super::providers::microsoft::fetch_user_info(
            &provider.config,
            options,
            request,
            claims,
        )
        .await;
    }
    if provider.config.is_paypal() {
        let claims = match claims {
            Some(VerifiedIdToken::PayPal(claims)) => Some(claims),
            None => None,
            Some(_) => return Err(AuthError::internal("Non-PayPal claims supplied to PayPal")),
        };
        return super::providers::paypal::fetch_user_info(
            &provider.config,
            request,
            expected_nonce,
            claims,
        )
        .await;
    }
    if let Some(options) = provider.config.facebook_options() {
        let claims = match claims {
            Some(VerifiedIdToken::Facebook(claims)) => Some(claims),
            None if request.id_token.is_truthy()? => {
                let token = request.id_token.field_value();
                let token = super::providers::jwt_string(&token)
                    .map_err(|_| AuthError::type_error("token.idToken.split is not a function"))?;
                if token.split('.').count() == 3 {
                    Some(
                        options
                            .verify(&provider.config.client_id, &token, expected_nonce)
                            .await?,
                    )
                } else {
                    None
                }
            }
            None => None,
            Some(_) => {
                return Err(AuthError::internal(
                    "Non-Facebook claims supplied to Facebook",
                ));
            }
        };
        return super::providers::facebook::fetch_user_info(
            &provider.config,
            options,
            request,
            claims,
        )
        .await;
    }
    if let Some(options) = provider.config.cognito_options() {
        let claims = match claims {
            Some(VerifiedIdToken::Cognito(claims)) => Some(claims),
            None if request.id_token.is_truthy()? => {
                let token = request.id_token.field_value();
                let token = super::providers::jwt_string(&token)?;
                Some(
                    options
                        .verify(&provider.config.client_id, &token, expected_nonce)
                        .await?,
                )
            }
            None => None,
            Some(_) => {
                return Err(AuthError::internal(
                    "Non-Cognito claims supplied to Cognito",
                ));
            }
        };
        return super::cognito::fetch_user_info(&provider.config, request, claims).await;
    }
    let claims = match claims {
        Some(VerifiedIdToken::Apple(claims)) if provider.config.apple_options().is_some() => {
            Some(VerifiedIdToken::Apple(claims))
        }
        Some(VerifiedIdToken::Google(claims)) if provider.config.paybin_issuer().is_none() => {
            Some(VerifiedIdToken::Google(claims))
        }
        Some(VerifiedIdToken::Paybin(claims)) if provider.config.paybin_issuer().is_some() => {
            Some(VerifiedIdToken::Paybin(claims))
        }
        None => {
            if let Some(issuer) = provider.config.paybin_issuer() {
                if !request.id_token.is_truthy()? {
                    return Ok(ProviderProfile::default());
                }
                let token = request.id_token.field_value();
                let token = super::providers::jwt_string(&token)?;
                Some(VerifiedIdToken::Paybin(
                    super::providers::paybin::verify(
                        issuer,
                        &provider.config.client_id,
                        &token,
                        expected_nonce,
                    )
                    .await?,
                ))
            } else {
                None
            }
        }
        Some(_) => {
            return Err(AuthError::internal(
                if provider.config.paybin_issuer().is_some() {
                    "Non-Paybin claims supplied to Paybin"
                } else {
                    "Non-Google claims supplied to a Social provider"
                },
            ));
        }
    };
    if (provider.config.is_atlassian() || provider.config.is_vk())
        && !request.access_token.is_truthy()?
    {
        return Ok(ProviderProfile::default());
    }
    match fetch_default_user_info(provider, request, claims).await {
        Ok(response)
            if !response.value.is_truthy()
                && (provider.config.is_figma() || provider.config.is_salesforce()) =>
        {
            better_auth_core::observability::logger::current().error(
                if provider.config.is_salesforce() {
                    "Failed to fetch user info from Salesforce"
                } else {
                    "Failed to fetch user from Figma"
                },
                &[],
            )?;
            Ok(response)
        }
        Err(error)
            if provider.config.is_figma()
                || provider.config.is_atlassian()
                || provider.config.is_salesforce() =>
        {
            // Atlassian retains the Figma diagnostic from its pinned default-profile catch.
            better_auth_core::observability::logger::current().error(
                if provider.config.is_salesforce() {
                    "Failed to fetch user info from Salesforce:"
                } else {
                    "Failed to fetch user info from Figma:"
                },
                &[better_auth_core::observability::LogArgument::Error(&error)],
            )?;
            Ok(ProviderProfile::default())
        }
        response => response,
    }
}

pub(super) async fn fetch_user_info_for_code(
    provider: &ResolvedProvider,
    request: OAuthUserInfoRequest,
    expected_nonce: Option<&str>,
) -> AuthResult<ProviderProfile> {
    if let Some(generic) = &provider.generic {
        return match super::generic_profile::fetch_profile(generic, &request, None).await {
            Ok(response) => Ok(response.into()),
            Err(super::generic_profile::GenericProfileError::Identity(_)) => {
                Ok(ProviderProfile::default())
            }
            Err(super::generic_profile::GenericProfileError::Profile(error)) => Err(error),
        };
    }
    let claims = if provider.config.get_user_info.is_none()
        && let Some(jwks_url) = provider.config.google_jwks_url()
    {
        if !request.id_token.is_truthy()? {
            return Ok(ProviderProfile::default());
        }
        let token = request.id_token.field_value();
        let Ok(token) = super::providers::jwt_string(&token) else {
            return Ok(ProviderProfile::default());
        };
        let Some(claims) = google::verify(
            &token,
            &provider.config.google_client_ids(),
            expected_nonce,
            jwks_url,
        )
        .await
        else {
            return Ok(ProviderProfile::default());
        };
        Some(VerifiedIdToken::Google(claims))
    } else {
        None
    };
    fetch_user_info_with_claims(provider, request, expected_nonce, claims).await
}

async fn map_legacy_profile(
    provider: &ResolvedProvider,
    response: OAuthUserInfoResponse,
) -> AuthResult<ProviderProfile> {
    let placeholder_id = response.user.id.clone();
    let mut response = ProviderProfile::from_typed(&provider.config, response)?;
    let data = response.value.model_property("data")?;
    let mapped = if !provider.config.is_tiktok()
        && let Some(mapper) = &provider.config.map_profile_to_user
    {
        mapper.map_profile_native(&data).await?
    } else {
        FieldValue::Undefined
    };
    if provider.config.is_vk()
        && !data
            .model_property("user")?
            .model_property("email")?
            .is_truthy()
        && !mapped_property(&mapped, "email")?.is_truthy()
    {
        return Ok(ProviderProfile::default());
    }
    let mut user = response.value.model_property("user")?.enumerable_fields()?;
    let placeholder_namespace = if provider.config.is_twitter() {
        Some("twitter")
    } else if provider.config.is_roblox() {
        Some("roblox")
    } else if provider.config.is_tiktok() {
        Some("tiktok")
    } else if provider.config.wechat_refresh_url().is_some() {
        Some("wechat")
    } else {
        None
    };
    if let Some(namespace) = placeholder_namespace
        && !user.get("email").is_some_and(FieldValue::is_truthy)
    {
        let _ = user.insert(
            "email".into(),
            placeholder_email(&placeholder_id, namespace)?.into(),
        );
    }
    let reddit_email = if provider.config.is_reddit() {
        let email = mapped_property(&mapped, "email")?;
        Some(if email.is_truthy() {
            email
        } else {
            placeholder_email(&placeholder_id, "reddit")?.into()
        })
    } else {
        None
    };
    user.extend(mapped.enumerable_fields()?);
    if let Some(email) = reddit_email {
        let _ = user.insert("email".into(), email);
        let verified = mapped_property(&mapped, "emailVerified")?;
        let _ = user.insert(
            "emailVerified".into(),
            if verified.is_null() || verified.is_undefined() {
                FieldValue::Bool(false)
            } else {
                verified
            },
        );
    }
    response.replace_user(user)?;
    Ok(response)
}

fn mapped_property(mapped: &FieldValue, name: &str) -> AuthResult<FieldValue> {
    if mapped.is_null() || mapped.is_undefined() {
        Ok(FieldValue::Undefined)
    } else {
        mapped.model_property(name)
    }
}

async fn fetch_default_user_info(
    provider: &ResolvedProvider,
    request: OAuthUserInfoRequest,
    claims: Option<VerifiedIdToken>,
) -> AuthResult<ProviderProfile> {
    if let Some((user_url, emails_url)) = provider.config.github_endpoints() {
        return super::providers::github_profile(
            user_url,
            emails_url,
            &request,
            provider.config.map_profile_to_user.as_deref(),
        )
        .await
        .map(Option::unwrap_or_default);
    }
    if provider.config.is_twitter() {
        return match super::providers::twitter::fetch_user_info(&provider.config, &request).await? {
            Some(response) => map_legacy_profile(provider, response).await,
            None => Ok(ProviderProfile::default()),
        };
    }
    if provider.config.wechat_refresh_url().is_some() {
        return match super::providers::wechat::fetch_user_info(&provider.config, &request).await? {
            Some(response) => map_legacy_profile(provider, response).await,
            None => Ok(ProviderProfile::default()),
        };
    }
    let data = match claims {
        Some(VerifiedIdToken::Apple(claims)) => {
            let Some(profile) = super::providers::apple::profile(&request, Some(claims))? else {
                return Ok(ProviderProfile::default());
            };
            profile
        }
        Some(VerifiedIdToken::Google(claims)) => claims.into_value(),
        Some(VerifiedIdToken::Paybin(claims)) => claims,
        Some(_) => return Err(AuthError::internal("Unexpected verified Social profile")),
        None if provider.config.google_jwks_url().is_some() => {
            if !request.id_token.is_truthy()? {
                return Ok(ProviderProfile::default());
            }
            let token = request.id_token.field_value();
            super::generic_profile::decode_claims(&super::providers::jwt_string(&token)?)
                .ok_or_else(|| AuthError::internal("Invalid Google ID-token claims"))?
        }
        None if provider.config.twitch_options().is_some() => {
            let Some(profile) = super::providers::twitch::fetch_profile(&request)? else {
                return Ok(ProviderProfile::default());
            };
            profile
        }
        None if provider.config.apple_options().is_some() => {
            let Some(profile) = super::providers::apple::profile(&request, None)? else {
                return Ok(ProviderProfile::default());
            };
            profile
        }
        None if provider.config.line_verify_url().is_some() => {
            let Some(profile) =
                super::providers::line::fetch_profile(&provider.config, &request).await?
            else {
                return Ok(ProviderProfile::default());
            };
            profile
        }
        None => {
            let user_info_url = provider
                .config
                .user_info_url
                .as_deref()
                .ok_or_else(|| AuthError::internal("Missing user_info_url for provider"))?;
            let access_token = request.access_token.field_value();
            let request = provider
                .config
                .user_info_request(user_info_url, &access_token)?;
            let response = http::fetch_native(request).await?;
            let Some(profile) = provider
                .config
                .http_profile_data(&response.data, &response.error)?
            else {
                return Ok(ProviderProfile::default());
            };
            if let Some(result) = provider
                .config
                .native_default_profile(&profile, &response.data)
                .await?
            {
                return Ok(result);
            }
            profile
                .json()?
                .ok_or_else(|| AuthError::internal("Legacy JSON provider profile is undefined"))?
        }
    };
    if provider.config.google_jwks_url().is_some() {
        if !google::hosted_domain_allowed(provider.config.google_hosted_domain(), &data) {
            let domain = data
                .get("hd")
                .filter(|value| !value.is_null())
                .cloned()
                .map(FieldValue::from)
                .unwrap_or_else(|| "<missing>".into())
                .display_utf16()?;
            better_auth_core::observability::logger::current().error(
                &format!(
                    "Google sign-in rejected: id token hosted domain (hd) \"{}\" does not satisfy the configured \"hd\" option \"{}\".",
                    String::from_utf16_lossy(domain.as_utf16()),
                    provider.config.google_hosted_domain().unwrap_or_default(),
                ),
                &[],
            )?;
            return Ok(ProviderProfile::default());
        }
        let profile = FieldValue::from(data.clone());
        if let Some(response) = provider
            .config
            .native_default_profile(&profile, &profile)
            .await?
        {
            return Ok(response);
        }
    }
    match provider.config.decode_profile(data.clone())? {
        Some(user) => map_legacy_profile(provider, OAuthUserInfoResponse { user, data }).await,
        None => Ok(ProviderProfile::default()),
    }
}

pub(super) fn missing_profile() -> AuthError {
    AuthError::from_code(
        "UNAUTHORIZED",
        "FAILED_TO_GET_USER_INFO",
        "Failed to get user info",
    )
}

pub(super) fn placeholder_email(identifier: &str, namespace: &str) -> AuthResult<String> {
    let email = format!("{identifier}@{namespace}.placeholder.invalid");
    if !crate::plugins::json_body::valid_email(&email)? {
        return Err(AuthError::type_error("Invalid placeholder email"));
    }
    Ok(email)
}

#[cfg(test)]
#[path = "profile_presence_tests.rs"]
mod tests;
