use base64::Engine;
use chrono::{Duration, Utc};
use indexmap::IndexMap;
use rand::RngCore;
use sha2::{Digest, Sha256};

use better_auth_core::entity::AuthSession;
use better_auth_core::session::NativeSessionData;
use better_auth_core::wire::UserView;
use better_auth_core::{
    AuthContext, AuthError, AuthRequest, AuthResponse, AuthResult, CreateAccount,
    CreateVerification, FieldMap, FieldValue, UpdateAccount, UpdateUser,
};

use super::authorization::{AuthorizationRequest, build_authorization_url};
use super::encryption::encrypt_token_set;
pub(super) use super::provider_tokens::refresh_tokens_via_provider;
use super::providers::OAuthUserInfoRequest;
use super::resolved::{ResolvedOAuthConfig as OAuthConfig, ResolvedProvider};
pub(super) use super::social_profile::{fetch_user_info_for_code, fetch_user_info_from_provider};
use super::state::{
    AccountCookiePayload, OAuthStateLink, OAuthStatePayload, account_cookie_name,
    create_account_cookie_value, create_cookie_state_value, create_database_state_cookie_value,
    decode_account_cookie_value, filter_additional_state_data, state_cookie_name,
};
use super::types::{
    LinkSocialRequest, OAuthIdTokenRequest, SocialSignInRequest, SocialSignInResponse,
};

use super::signin::{OAuthSignInOptions, process_oauth_sign_in};

// ---------------------------------------------------------------------------
// Shared helpers (DRY)
// ---------------------------------------------------------------------------

fn random_base64url(bytes: usize) -> String {
    let mut random = vec![0; bytes];
    rand::thread_rng().fill_bytes(&mut random);
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(random)
}

fn generate_pkce() -> (String, String) {
    let verifier = random_base64url(96);
    let mut hasher = Sha256::new();
    hasher.update(verifier.as_bytes());
    let challenge = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(hasher.finalize());
    (verifier, challenge)
}

pub(super) fn callback_user_request(
    tokens: &FieldValue,
    user_data: &FieldValue,
    expected_nonce: Option<&str>,
) -> AuthResult<OAuthUserInfoRequest> {
    let user = if user_data.is_truthy() {
        better_auth_core::utils::json::safe_parse_field(user_data)?
    } else {
        FieldValue::Null
    };
    let mut fields = tokens.enumerable_fields()?;
    if let Some(nonce) = expected_nonce.filter(|nonce| !nonce.is_empty()) {
        let _ = fields.insert("expectedIdTokenNonce".into(), nonce.into());
    }
    let _ = fields.insert(
        "user".into(),
        if user.is_null() {
            FieldValue::Undefined
        } else {
            user
        },
    );
    Ok(OAuthUserInfoRequest::from_fields(fields))
}

pub(super) fn redirect_response(location: &str) -> AuthResponse {
    AuthResponse::new(302)
        .with_header("content-type", "application/json")
        .with_header("Location", location)
}

fn account_cookie_max_age(config: &better_auth_core::AuthConfig) -> Duration {
    config
        .session
        .cookie_cache
        .as_ref()
        .map(|cache| cache.max_age())
        .unwrap_or_else(|| Duration::minutes(5))
}

pub(super) fn create_account_cookie_headers(
    req: &AuthRequest,
    config: &better_auth_core::AuthConfig,
    payload: &AccountCookiePayload,
) -> AuthResult<Vec<String>> {
    let max_age = account_cookie_max_age(config);
    let cookie = config.auth_cookie(
        "account_data",
        better_auth_core::CookieAttributes {
            max_age: Some(max_age.as_seconds_f64()),
            ..Default::default()
        },
    );
    let ttl = cookie.attributes.max_age.unwrap_or(300.0);
    let value = create_account_cookie_value(config.encryption_secret(), payload, ttl)?;
    better_auth_core::utils::cookie_utils::create_chunked_cookies(req, &cookie, &value)
}

pub(super) fn decode_account_cookie(
    req: &AuthRequest,
    config: &better_auth_core::AuthConfig,
) -> AuthResult<Option<AccountCookiePayload>> {
    let Some(value) = better_auth_core::utils::cookie_utils::get_chunked_cookie(
        req,
        &account_cookie_name(config),
    ) else {
        return Ok(None);
    };
    Ok(decode_account_cookie_value(
        config.encryption_secret(),
        &value,
    ))
}

pub(super) fn attach_state_cookie(
    response: AuthResponse,
    config: &better_auth_core::AuthConfig,
    state: &str,
) -> AuthResult<AuthResponse> {
    let value = create_database_state_cookie_value(config.signing_secret(), state)?;
    Ok(response.with_appended_header(
        "Set-Cookie",
        better_auth_core::utils::cookie_utils::create_cookie(
            &state_cookie_name(config),
            &value,
            Duration::minutes(5).as_seconds_f64(),
            config,
        )?,
    ))
}

pub(super) fn attach_cookie_state_payload(
    response: AuthResponse,
    config: &better_auth_core::AuthConfig,
    payload: &OAuthStatePayload,
) -> AuthResult<AuthResponse> {
    let value = create_cookie_state_value(config.encryption_secret(), payload)?;
    Ok(response.with_appended_header(
        "Set-Cookie",
        better_auth_core::utils::cookie_utils::create_cookie(
            &state_cookie_name(config),
            &value,
            Duration::minutes(10).as_seconds_f64(),
            config,
        )?,
    ))
}

pub(crate) fn validate_redirect_target(
    target: &str,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
    error_message: &str,
) -> AuthResult<()> {
    if ctx.config.advanced.disable_origin_check {
        return Ok(());
    }
    if ctx.is_redirect_target_trusted(target) {
        Ok(())
    } else {
        Err(AuthError::forbidden(error_message.to_string()))
    }
}

pub(super) fn auth_base_url(ctx: &AuthContext<impl better_auth_core::AuthSchema>) -> String {
    ctx.base_url().trim_end_matches('/').to_owned()
}

pub(super) fn state_callback_url<'a>(
    callback: Option<&'a str>,
    ctx: &'a AuthContext<impl better_auth_core::AuthSchema>,
) -> AuthResult<&'a str> {
    callback
        .filter(|value| !value.is_empty())
        .or_else(|| {
            ctx.config
                .base_url
                .as_static()
                .filter(|value| !value.is_empty())
        })
        .ok_or_else(|| AuthError::bad_request("callbackURL is required"))
}

pub(super) struct InitiatedOAuthFlow {
    pub(super) response: SocialSignInResponse,
    pub(super) state: String,
    pub(super) payload: OAuthStatePayload,
}

pub(super) struct FlowStartRequest<'a> {
    pub(super) anonymous_user_id: Option<String>,
    pub(super) provider_name: &'a str,
    pub(super) provider: &'a ResolvedProvider,
    pub(super) callback_url: &'a str,
    pub(super) new_user_callback_url: Option<String>,
    pub(super) error_callback_url: Option<String>,
    pub(super) scopes: Option<&'a [String]>,
    pub(super) additional_params: Option<&'a IndexMap<String, String>>,
    pub(super) login_hint: Option<&'a str>,
    pub(super) request_sign_up: Option<bool>,
    pub(super) additional_data: super::state_json::StateExtras,
    pub(super) link: Option<OAuthStateLink>,
    pub(super) disable_redirect: bool,
}

pub(super) enum OAuthLinkOutcome {
    Linked,
    Failed {
        code: String,
        description: Option<String>,
    },
}

impl OAuthLinkOutcome {
    fn failed(code: &str) -> Self {
        Self::Failed {
            code: code.to_owned(),
            description: None,
        }
    }
}

pub(super) async fn complete_link_social(
    user_info: &FieldValue,
    account: &FieldMap,
    scopes: &better_auth_core::SchemaValue<Vec<String>>,
    link: &OAuthStateLink,
    profile: Option<&FieldValue>,
    endpoint: &crate::plugins::endpoint_context::EndpointContext<
        '_,
        impl better_auth_core::AuthSchema,
    >,
) -> AuthResult<OAuthLinkOutcome> {
    let provider_id = account.get("providerId").cloned().unwrap_or_default();
    let account_id = account.get("accountId").cloned().unwrap_or_default();
    let ctx = endpoint.auth;
    if let Err(error) = async {
        let mut user = user_info.enumerable_fields()?;
        let _ = user.insert("id".into(), link.user_id().clone());
        let email = user_info.model_property("email")?;
        let _ = user.insert(
            "email".into(),
            if email.is_null() {
                FieldValue::Undefined
            } else {
                email
            },
        );
        crate::plugins::user_admission::validate(
            crate::plugins::user_admission::UserValidationData {
                user,
                source: crate::plugins::user_admission::UserValidationSource::explicit_oauth_link(
                    &provider_id,
                    profile,
                ),
            },
            endpoint,
        )
        .await
        .map_err(crate::plugins::user_admission::UserValidationRejection::into_auth_error)
    }
    .await
    {
        let (code, description) = super::signin::OAuthSignInError::Auth(error).redirect_parts()?;
        return Ok(OAuthLinkOutcome::Failed { code, description });
    }
    let linking = &ctx.config.account.account_linking;
    let trusted_provider = ctx
        .trusted_providers()
        .iter()
        .any(|trusted| provider_id.strict_equals(&trusted.as_str().into()));

    if (!trusted_provider && !user_info.model_property("emailVerified")?.is_truthy())
        || !linking.enabled()
    {
        return Ok(OAuthLinkOutcome::failed("unable_to_link_account"));
    }

    let email = user_info.model_property("email")?;
    let provider_email = if email.is_null() || email.is_undefined() {
        FieldValue::Undefined
    } else {
        super::native_user::lowercase(&email, "userInfo.email")?
    };
    if !provider_email.strict_equals(&super::native_user::lowercase(link.email(), "link.email")?)
        && !linking.allow_different_emails
    {
        return Ok(OAuthLinkOutcome::failed("email_doesn't_match"));
    }

    if let Some(existing_account) = ctx
        .database
        .get_account_value(&provider_id, &account_id)
        .await?
    {
        let account_owner = existing_account.user_id.field_value();
        if matches!(account_owner, FieldValue::Null | FieldValue::Undefined) {
            let kind = if account_owner.is_null() {
                "null"
            } else {
                "undefined"
            };
            return Err(AuthError::type_error(format!(
                "{kind} is not an object (evaluating 'existingAccount.userId.toString')"
            )));
        }
        if account_owner.display_utf16()? != link.user_id().display_utf16()? {
            return Ok(OAuthLinkOutcome::failed(
                "account_already_linked_to_different_user",
            ));
        }

        let merged_scope =
            super::providers::merge_scopes(&existing_account.scope.field_value(), scopes)?;
        let token_bundle = encrypt_token_set(
            ctx,
            better_auth_core::SchemaValue::Dynamic(
                account.get("accessToken").cloned().unwrap_or_default(),
            ),
            better_auth_core::SchemaValue::Dynamic(
                account.get("refreshToken").cloned().unwrap_or_default(),
            ),
            better_auth_core::SchemaValue::Dynamic(
                account.get("idToken").cloned().unwrap_or_default(),
            ),
        )?;
        let mut fields = FieldMap::from([
            ("providerId".into(), provider_id.clone()),
            (
                "accessToken".into(),
                token_bundle.access_token.into_field_value(),
            ),
            (
                "refreshToken".into(),
                token_bundle.refresh_token.into_field_value(),
            ),
            ("idToken".into(), token_bundle.id_token.into_field_value()),
            (
                "accessTokenExpiresAt".into(),
                account
                    .get("accessTokenExpiresAt")
                    .cloned()
                    .unwrap_or_default(),
            ),
            (
                "refreshTokenExpiresAt".into(),
                account
                    .get("refreshTokenExpiresAt")
                    .cloned()
                    .unwrap_or_default(),
            ),
            (
                "scope".into(),
                if merged_scope.is_truthy() {
                    merged_scope
                } else {
                    FieldValue::Undefined
                },
            ),
        ]);
        fields.retain(|_, value| !value.is_undefined());

        let _ = ctx
            .database
            .update_account_by_id_value(
                &existing_account.id.field_value(),
                UpdateAccount {
                    additional_fields: fields,
                    ..Default::default()
                },
            )
            .await?;

        let _ = apply_link_user_info(link.user_id(), user_info, ctx).await;
        return Ok(OAuthLinkOutcome::Linked);
    }

    let token_bundle = encrypt_token_set(
        ctx,
        better_auth_core::SchemaValue::Dynamic(
            account.get("accessToken").cloned().unwrap_or_default(),
        ),
        better_auth_core::SchemaValue::Dynamic(
            account.get("refreshToken").cloned().unwrap_or_default(),
        ),
        better_auth_core::SchemaValue::Dynamic(account.get("idToken").cloned().unwrap_or_default()),
    )?;
    let mut fields = FieldMap::from([("userId".into(), link.user_id().clone())]);
    fields.extend(account.clone());
    let scope = super::providers::joined_scopes(&scopes.field_value())?;
    fields.extend([
        (
            "accessToken".into(),
            token_bundle.access_token.into_field_value(),
        ),
        (
            "refreshToken".into(),
            token_bundle.refresh_token.into_field_value(),
        ),
        (
            "scope".into(),
            if scope.is_undefined() {
                account.get("scope").cloned().unwrap_or_default()
            } else {
                scope
            },
        ),
    ]);
    let account = ctx
        .database
        .create_account_optional(CreateAccount {
            additional_fields: fields,
            ..Default::default()
        })
        .await?;
    if account.is_none() {
        return Ok(OAuthLinkOutcome::failed("unable_to_link_account"));
    }

    let _ = apply_link_user_info(link.user_id(), user_info, ctx).await;
    Ok(OAuthLinkOutcome::Linked)
}

async fn sign_in_with_id_token_core(
    req: &AuthRequest,
    body: &SocialSignInRequest,
    id_token: &OAuthIdTokenRequest,
    provider: &ResolvedProvider,
    config: &OAuthConfig,
    meta: &better_auth_core::RequestMeta,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
) -> AuthResult<AuthResponse> {
    let mut endpoint = crate::plugins::endpoint_context::EndpointContext::new(
        Some(req),
        req.input_field_value()?,
        ctx,
    );
    endpoint.session = req.native_session_snapshot()?;
    let claims =
        super::id_token::verify_in_endpoint(&body.provider, provider, id_token, &endpoint).await?;

    let subject_tokens: FieldValue = FieldMap::from([
        ("idToken".into(), id_token.token.clone().into()),
        (
            "accessToken".into(),
            id_token
                .access_token
                .clone()
                .map(Into::into)
                .unwrap_or_default(),
        ),
        (
            "refreshToken".into(),
            id_token
                .refresh_token
                .clone()
                .map(Into::into)
                .unwrap_or_default(),
        ),
        (
            "user".into(),
            id_token
                .user
                .clone()
                .map(better_auth_core::SchemaField::into_field)
                .unwrap_or_default(),
        ),
    ])
    .into();
    let user_info = super::social_profile::fetch_user_info_with_claims(
        provider,
        OAuthUserInfoRequest::from_fields(subject_tokens.enumerable_fields()?),
        id_token.nonce.as_deref(),
        claims,
    )
    .await?;
    if !user_info.value.is_truthy() || !user_info.value.model_property("user")?.is_truthy() {
        return Err(super::social_profile::missing_profile());
    }
    if !user_info
        .value
        .model_property("user")?
        .model_property("email")?
        .is_truthy()
    {
        return Err(AuthError::from_code(
            "UNAUTHORIZED",
            "USER_EMAIL_NOT_FOUND",
            "User email not found",
        ));
    }

    let account_id = super::social_profile::resolve_account_subject(
        provider,
        &subject_tokens,
        &user_info.value.model_property("data")?,
        user_info.legacy_subject.as_ref(),
    )
    .await
    .map_err(|_| super::social_profile::missing_profile())?;
    let provider_profile = user_info.value.model_property("data")?;
    let user = super::native_user::direct_user(&user_info.value, account_id.clone())?;

    let outcome = match process_oauth_sign_in(
        &body.provider,
        provider,
        &user,
        &FieldMap::from([
            ("providerId".into(), body.provider.clone().into()),
            ("accountId".into(), account_id.clone()),
            (
                "accessToken".into(),
                id_token
                    .access_token
                    .clone()
                    .map(Into::into)
                    .unwrap_or_default(),
            ),
            ("idToken".into(), id_token.token.clone().into()),
        ]),
        OAuthSignInOptions {
            request: req,
            profile: Some(&provider_profile),
            body: req.body_as_json()?,
            disable_sign_up: provider.config.disable_implicit_sign_up()
                && !body.request_sign_up.unwrap_or(false)
                || provider.config.disable_sign_up(),
            override_user_info: false,
            callback_url: body.callback_url.as_deref().unwrap_or("/"),
            email_verification: config.email_verification.as_deref(),
        },
        meta,
        ctx,
    )
    .await
    {
        Ok(outcome) => outcome,
        Err(error) => return error.into_auth_response(),
    };

    ctx.session_manager()
        .set_native_session_cookie(req, outcome.issued.clone(), None)
        .await?;
    let response = better_auth_core::FieldMap::from([
        ("redirect".into(), false.into()),
        ("token".into(), outcome.issued.session.token().field_value()),
        ("url".into(), better_auth_core::FieldValue::Undefined),
        ("user".into(), outcome.issued.public_user(&ctx.config.user)?),
    ]);
    Ok(AuthResponse::native(None, response.into()))
}

async fn link_with_id_token_core(
    req: &AuthRequest,
    body: &LinkSocialRequest,
    id_token: &OAuthIdTokenRequest,
    provider: &ResolvedProvider,
    current_session: &NativeSessionData,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
) -> AuthResult<SocialSignInResponse> {
    let mut endpoint = crate::plugins::endpoint_context::EndpointContext::new(
        Some(req),
        req.input_field_value()?,
        ctx,
    );
    endpoint.session = req.native_session_snapshot()?;
    let claims =
        super::id_token::verify_in_endpoint(&body.provider, provider, id_token, &endpoint).await?;

    let subject_tokens: FieldValue = FieldMap::from([
        ("idToken".into(), id_token.token.clone().into()),
        (
            "accessToken".into(),
            id_token
                .access_token
                .clone()
                .map(Into::into)
                .unwrap_or_default(),
        ),
        (
            "refreshToken".into(),
            id_token
                .refresh_token
                .clone()
                .map(Into::into)
                .unwrap_or_default(),
        ),
    ])
    .into();
    let response = super::social_profile::fetch_user_info_with_claims(
        provider,
        OAuthUserInfoRequest::from_fields(subject_tokens.enumerable_fields()?),
        id_token.nonce.as_deref(),
        claims,
    )
    .await?;
    if !response.value.is_truthy() || !response.value.model_property("user")?.is_truthy() {
        return Err(super::social_profile::missing_profile());
    }
    if !response
        .value
        .model_property("user")?
        .model_property("email")?
        .is_truthy()
    {
        return Err(AuthError::from_code(
            "UNAUTHORIZED",
            "USER_EMAIL_NOT_FOUND",
            "User email not found",
        ));
    };

    let account_id = super::social_profile::resolve_account_subject(
        provider,
        &subject_tokens,
        &response.value.model_property("data")?,
        response.legacy_subject.as_ref(),
    )
    .await
    .map_err(|_| super::social_profile::missing_profile())?;
    let account = ctx
        .database
        .get_account_value(&body.provider.as_str().into(), &account_id)
        .await?;
    let current_user_id = current_session.user_property("id")?;
    let account_user_id = account
        .as_ref()
        .map(|account| account.user_id.field_value())
        .unwrap_or(FieldValue::Undefined);
    if account_user_id.strict_equals(&current_user_id) {
        let tokens = encrypt_token_set(
            ctx,
            id_token
                .access_token
                .clone()
                .map(|value| Some(value).into())
                .unwrap_or_default(),
            id_token
                .refresh_token
                .clone()
                .map(|value| Some(value).into())
                .unwrap_or_default(),
            Some(id_token.token.clone()).into(),
        )?;
        let mut fields = FieldMap::from([
            ("providerId".into(), body.provider.clone().into()),
            ("accessToken".into(), tokens.access_token.into_field_value()),
            ("idToken".into(), tokens.id_token.into_field_value()),
            (
                "refreshToken".into(),
                tokens.refresh_token.into_field_value(),
            ),
        ]);
        fields.retain(|_, value| !value.is_undefined());
        let account = account.as_ref().ok_or_else(|| {
            AuthError::type_error("null is not an object (evaluating 'linkedAccount.id')")
        })?;
        let _ = ctx
            .database
            .update_account_by_id_value(
                &account.id.field_value(),
                UpdateAccount {
                    additional_fields: fields,
                    ..Default::default()
                },
            )
            .await?;
        let _ = apply_link_user_info(
            &current_user_id,
            &response.value.model_property("user")?,
            ctx,
        )
        .await;
        return Ok(SocialSignInResponse {
            url: Some(String::new()),
            redirect: false,
            status: Some(true),
        });
    }
    if account.is_some() {
        return Err(AuthError::from_code(
            "CONFLICT",
            "SOCIAL_ACCOUNT_ALREADY_LINKED",
            "Social account already linked",
        ));
    }

    let linking = &ctx.config.account.account_linking;
    let trusted_provider = ctx
        .trusted_providers()
        .iter()
        .any(|trusted| trusted == &body.provider);

    if (!trusted_provider
        && !response
            .value
            .model_property("user")?
            .model_property("emailVerified")?
            .is_truthy())
        || !linking.enabled()
    {
        return Err(AuthError::from_code(
            "UNAUTHORIZED",
            "LINKING_NOT_ALLOWED",
            "Account not linked - linking not allowed",
        ));
    }
    let email = response
        .value
        .model_property("user")?
        .model_property("email")?;
    let provider_email = if email.is_null() || email.is_undefined() {
        FieldValue::Undefined
    } else {
        super::native_user::lowercase(&email, "linkingUserInfo.user.email")?
    };
    if !provider_email.strict_equals(&super::native_user::lowercase(
        &current_session.user_property("email")?,
        "session.user.email",
    )?) && !linking.allow_different_emails
    {
        return Err(AuthError::from_code(
            "UNAUTHORIZED",
            "LINKING_DIFFERENT_EMAILS_NOT_ALLOWED",
            "Account not linked - different emails not allowed",
        ));
    }

    let created = async {
        let token_bundle = encrypt_token_set(
            ctx,
            id_token
                .access_token
                .clone()
                .map(|value| Some(value).into())
                .unwrap_or_default(),
            id_token
                .refresh_token
                .clone()
                .map(|value| Some(value).into())
                .unwrap_or_default(),
            Some(id_token.token.clone()).into(),
        )?;
        let _ = ctx
            .database
            .create_account_optional(CreateAccount {
                additional_fields: FieldMap::from([
                    ("userId".into(), current_user_id.clone()),
                    ("providerId".into(), body.provider.clone().into()),
                    ("accountId".into(), account_id.clone()),
                    (
                        "accessToken".into(),
                        token_bundle.access_token.into_field_value(),
                    ),
                    ("idToken".into(), token_bundle.id_token.into_field_value()),
                    (
                        "refreshToken".into(),
                        token_bundle.refresh_token.into_field_value(),
                    ),
                ]),
                ..Default::default()
            })
            .await?;
        Ok::<_, AuthError>(())
    }
    .await;
    if created.is_err() {
        return Err(AuthError::try_api_error(better_auth_core::ApiErrorInit {
            status: "EXPECTATION_FAILED".into(),
            body: FieldMap::from([
                (
                    "message".into(),
                    "Account not linked - unable to create account".into(),
                ),
                ("code".into(), "LINKING_FAILED".into()),
            ])
            .into(),
            ..Default::default()
        })?);
    }
    let _ = apply_link_user_info(
        &current_user_id,
        &response.value.model_property("user")?,
        ctx,
    )
    .await;

    Ok(SocialSignInResponse {
        url: Some(String::new()),
        redirect: false,
        status: Some(true),
    })
}

pub(super) async fn apply_link_user_info(
    user_id: &FieldValue,
    user_info: &FieldValue,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
) -> Option<UserView> {
    if !ctx
        .config
        .account
        .account_linking
        .update_user_info_on_link()
    {
        return None;
    }
    let result = async {
        ctx.database
            .update_user_by_id_value(
                user_id,
                UpdateUser {
                    additional_fields: {
                        let (name, image, profile) =
                            super::native_user::profile_fields(user_info, false)?;
                        let mut fields =
                            FieldMap::from([("name".into(), name), ("image".into(), image)]);
                        fields.extend(ctx.config.user.parse_provider_input(&profile, false)?);
                        fields
                    },
                    ..Default::default()
                },
            )
            .await
    }
    .await;
    // Upstream treats profile synchronization as optional after the account write succeeds.
    match result {
        Ok(user) => user,
        Err(error) => {
            better_auth_core::observability::logger::current().warn(
                "Could not update user info on account link",
                &[better_auth_core::observability::LogArgument::Error(&error)],
            );
            None
        }
    }
}

// ---------------------------------------------------------------------------
// Core functions
// ---------------------------------------------------------------------------

async fn social_sign_in_core(
    req: &AuthRequest,
    body: &SocialSignInRequest,
    config: &OAuthConfig,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
) -> AuthResult<InitiatedOAuthFlow> {
    let provider = config.providers.get(&body.provider).ok_or_else(|| {
        AuthError::from_code("NOT_FOUND", "PROVIDER_NOT_FOUND", "Provider not found")
    })?;

    let callback_url = state_callback_url(body.callback_url.as_deref(), ctx)?;
    super::proxy::validate_callback_url(req, callback_url, ctx)?;
    if let Some(error_callback_url) = body.error_callback_url.as_deref() {
        validate_redirect_target(error_callback_url, ctx, "Invalid errorCallbackURL")?;
    }
    if let Some(new_user_callback_url) = body.new_user_callback_url.as_deref() {
        validate_redirect_target(new_user_callback_url, ctx, "Invalid newUserCallbackURL")?;
    }

    let anonymous_user_id = req
        .server_context("anonymousUserId")?
        .and_then(|value| value.as_str().map(str::to_owned));
    initiate_oauth_flow_core(
        req,
        ctx,
        FlowStartRequest {
            anonymous_user_id,
            provider_name: &body.provider,
            provider,
            callback_url,
            new_user_callback_url: body.new_user_callback_url.clone(),
            error_callback_url: body.error_callback_url.clone(),
            scopes: body.scopes.as_deref(),
            additional_params: body.additional_params.as_ref(),
            login_hint: body.login_hint.as_deref(),
            request_sign_up: body.request_sign_up,
            additional_data: filter_additional_state_data(body.additional_data.clone())?,
            link: None,
            disable_redirect: body.disable_redirect.unwrap_or(false),
        },
    )
    .await
}

async fn link_social_core(
    req: &AuthRequest,
    body: &LinkSocialRequest,
    session: &NativeSessionData,
    config: &OAuthConfig,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
) -> AuthResult<InitiatedOAuthFlow> {
    let provider = config.providers.get(&body.provider).ok_or_else(|| {
        AuthError::from_code("NOT_FOUND", "PROVIDER_NOT_FOUND", "Provider not found")
    })?;

    let callback_url = state_callback_url(body.callback_url.as_deref(), ctx)?;
    super::proxy::validate_callback_url(req, callback_url, ctx)?;
    if let Some(error_callback_url) = body.error_callback_url.as_deref() {
        validate_redirect_target(error_callback_url, ctx, "Invalid errorCallbackURL")?;
    }

    initiate_oauth_flow_core(
        req,
        ctx,
        FlowStartRequest {
            anonymous_user_id: None,
            provider_name: &body.provider,
            provider,
            callback_url,
            new_user_callback_url: None,
            error_callback_url: body.error_callback_url.clone(),
            scopes: body.scopes.as_deref(),
            additional_params: body.additional_params.as_ref(),
            login_hint: body.login_hint.as_deref(),
            request_sign_up: body.request_sign_up,
            additional_data: filter_additional_state_data(body.additional_data.clone())?,
            link: Some(OAuthStateLink::new(
                session.user_property("id")?,
                session.user_property("email")?,
            )),
            disable_redirect: body.disable_redirect.unwrap_or(false),
        },
    )
    .await
}

pub(super) struct PreparedOAuthFlow {
    pub(super) state: String,
    pub(super) payload: OAuthStatePayload,
    code_challenge: String,
}

pub(super) fn prepare_oauth_flow(request: &FlowStartRequest<'_>) -> PreparedOAuthFlow {
    let (code_verifier, code_challenge) = generate_pkce();
    let state = random_base64url(24);
    let mut payload = OAuthStatePayload::new(
        request.callback_url.to_string(),
        code_verifier,
        request.error_callback_url.clone(),
        request.new_user_callback_url.clone(),
        request.link.clone(),
        request.request_sign_up,
        request.additional_data.clone(),
    );
    payload.oauth_state = Some(state.clone());
    if let Some(user_id) = &request.anonymous_user_id {
        let _ = payload
            .server_context
            .insert("anonymousUserId".into(), serde_json::json!(user_id));
    }
    payload.id_token_nonce = request
        .provider
        .requires_nonce()
        .then(|| random_base64url(24));
    PreparedOAuthFlow {
        state,
        payload,
        code_challenge,
    }
}

pub(super) async fn store_oauth_flow(
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
    flow: &PreparedOAuthFlow,
) -> AuthResult<()> {
    if matches!(
        ctx.config.account.store_state_strategy(),
        better_auth_core::OAuthStateStrategy::Database
    ) {
        let _ = ctx
            .database
            .create_verification_optional(CreateVerification {
                identifier: (flow.state.clone()).into(),
                value: (serde_json::to_string(&flow.payload)?).into(),
                expires_at: (Utc::now() + Duration::minutes(10)).into(),
                ..Default::default()
            })
            .await?;
    }
    Ok(())
}

pub(super) fn oauth_authorization_url(
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
    request: &FlowStartRequest<'_>,
    flow: &PreparedOAuthFlow,
) -> AuthResult<String> {
    build_authorization_url(
        request.provider,
        AuthorizationRequest {
            callback_url: &format!("{}/callback/{}", auth_base_url(ctx), request.provider_name),
            scopes: request.scopes,
            state: &flow.state,
            code_challenge: &flow.code_challenge,
            login_hint: request.login_hint,
            nonce: flow.payload.id_token_nonce.as_deref(),
            additional_params: request.additional_params,
        },
    )
}

/// Prepare, persist, and authorize a social sign-in or account-link flow.
pub(super) async fn initiate_oauth_flow_core(
    req: &AuthRequest,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
    request: FlowStartRequest<'_>,
) -> AuthResult<InitiatedOAuthFlow> {
    let flow = prepare_oauth_flow(&request);
    super::state_context::publish_generated(req, &flow.payload)?;
    store_oauth_flow(ctx, &flow).await?;
    let url = oauth_authorization_url(ctx, &request, &flow)?;
    Ok(InitiatedOAuthFlow {
        response: SocialSignInResponse {
            url: Some(url),
            redirect: !request.disable_redirect,
            status: None,
        },
        state: flow.state,
        payload: flow.payload,
    })
}

// ---------------------------------------------------------------------------
// Old handlers (rewritten to call core)
// ---------------------------------------------------------------------------

pub(crate) async fn handle_social_sign_in(
    config: &OAuthConfig,
    req: &AuthRequest,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
) -> AuthResult<AuthResponse> {
    let body: SocialSignInRequest = super::request::read(req)?;
    let meta = better_auth_core::RequestMeta::from_request_with_config(
        req,
        &ctx.config.advanced.ip_address,
    );
    if let Some(id_token) = &body.id_token {
        let provider = config.providers.get(&body.provider).ok_or_else(|| {
            AuthError::from_code("NOT_FOUND", "PROVIDER_NOT_FOUND", "Provider not found")
        })?;
        return sign_in_with_id_token_core(req, &body, id_token, provider, config, &meta, ctx)
            .await;
    }

    let flow = social_sign_in_core(req, &body, config, ctx).await?;
    let response = flow.response;
    let mut auth_response = AuthResponse::json(None, &response)?;

    if let Some(url) = response.url.as_deref()
        && response.redirect
    {
        auth_response = auth_response.with_header("Location", url);
    }

    match ctx.config.account.store_state_strategy() {
        better_auth_core::OAuthStateStrategy::Database => {
            attach_state_cookie(auth_response, &ctx.config, &flow.state)
        }
        better_auth_core::OAuthStateStrategy::Cookie => {
            attach_cookie_state_payload(auth_response, &ctx.config, &flow.payload)
        }
    }
}

pub(crate) async fn handle_link_social(
    config: &OAuthConfig,
    req: &AuthRequest,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
) -> AuthResult<AuthResponse> {
    let body: LinkSocialRequest = super::request::read(req)?;
    let session = ctx.require_native_session(req).await?;
    if let Some(id_token) = &body.id_token {
        let provider = config.providers.get(&body.provider).ok_or_else(|| {
            AuthError::from_code("NOT_FOUND", "PROVIDER_NOT_FOUND", "Provider not found")
        })?;
        let response =
            link_with_id_token_core(req, &body, id_token, provider, &session, ctx).await?;
        return AuthResponse::json(None, &response);
    }

    let flow = link_social_core(req, &body, &session, config, ctx).await?;
    let response = flow.response;
    let mut auth_response = AuthResponse::json(None, &response)?;

    if let Some(url) = response.url.as_deref()
        && response.redirect
    {
        auth_response = auth_response.with_header("Location", url);
    }

    match ctx.config.account.store_state_strategy() {
        better_auth_core::OAuthStateStrategy::Database => {
            attach_state_cookie(auth_response, &ctx.config, &flow.state)
        }
        better_auth_core::OAuthStateStrategy::Cookie => {
            attach_cookie_state_payload(auth_response, &ctx.config, &flow.payload)
        }
    }
}

#[cfg(test)]
#[path = "handlers_tests.rs"]
mod tests;
