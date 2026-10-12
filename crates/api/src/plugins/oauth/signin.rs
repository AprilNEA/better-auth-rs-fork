use better_auth_core::entity::{AuthSession, AuthUser};
use better_auth_core::wire::UserView;
use better_auth_core::{
    AuthContext, AuthError, AuthRequest, AuthResponse, AuthResult, CreateAccount, CreateUser,
    FieldValue, UpdateAccount, UpdateUser,
};

use super::encryption::encrypt_token_set;
use super::native_user::lower_email;
use super::providers::OAuthTokenSet;
use super::resolved::ResolvedProvider;
use super::state::AccountCookiePayload;
use crate::plugins::helpers::{
    SessionIssueError, apply_default_role, issue_selected_user_session_optional,
};

pub(super) struct OAuthSignInOptions<'a> {
    pub(super) request: &'a AuthRequest,
    pub(super) profile: Option<&'a FieldValue>,
    pub(super) body: serde_json::Value,
    pub(super) disable_sign_up: bool,
    pub(super) override_user_info: bool,
    pub(super) callback_url: &'a str,
    pub(super) email_verification:
        Option<&'a crate::plugins::email_verification::EmailVerificationPlugin>,
}

impl OAuthSignInOptions<'_> {
    fn set_account_cookie(
        &self,
        account: Option<&AccountCookiePayload>,
        ctx: &AuthContext<impl better_auth_core::AuthSchema>,
    ) -> AuthResult<()> {
        if !ctx.config.account.store_account_cookie() {
            return Ok(());
        }
        let account =
            account.ok_or_else(|| AuthError::type_error("JWT Claims Set MUST be an object"))?;
        for cookie in
            super::handlers::create_account_cookie_headers(self.request, &ctx.config, account)?
        {
            self.request.append_response_header("Set-Cookie", cookie)?;
        }
        Ok(())
    }

    async fn check_email_verification(
        &self,
        required: bool,
        user: Option<&UserView>,
        is_register: bool,
        ctx: &AuthContext<impl better_auth_core::AuthSchema>,
    ) -> Result<(), OAuthSignInError> {
        if let Some(plugin) = self.email_verification {
            plugin
                .send_verification_on_oauth_sign_in(
                    user,
                    is_register,
                    required,
                    self.callback_url,
                    self.request,
                    ctx,
                )
                .await;
        }
        if required && !user.is_some_and(|user| user.email_verified().field_value().is_truthy()) {
            return Err(OAuthSignInError::Generic("email_not_verified".to_owned()));
        }
        Ok(())
    }
}

pub(super) struct ProcessOAuthUserResult {
    pub(super) issued: better_auth_core::session::NativeSessionData,
    pub(super) is_register: bool,
}

pub(super) enum OAuthSignInError {
    Auth(AuthError),
    Generic(String),
    Banned(String),
}

impl OAuthSignInError {
    pub(super) fn into_auth_response(self) -> AuthResult<AuthResponse> {
        Ok(match self {
            Self::Auth(error) => return Err(error),
            Self::Generic(message) if message == "email_not_verified" => {
                AuthError::from_code("FORBIDDEN", "EMAIL_NOT_VERIFIED", "Email not verified")
                    .to_auth_response()
            }
            Self::Generic(message) => AuthResponse::json(
                401,
                &serde_json::json!({"code": "OAUTH_LINK_ERROR", "message": message}),
            )?,
            Self::Banned(message) => AuthError::banned_user(message).to_auth_response(),
        })
    }

    pub(super) fn redirect_parts(self) -> AuthResult<(String, Option<String>)> {
        Ok(match self {
            Self::Auth(error) => return api_error_redirect_parts(error),
            Self::Generic(message) => (message.replace(' ', "_"), None),
            Self::Banned(message) => (
                "BANNED_USER".into(),
                (!message.is_empty()).then_some(message),
            ),
        })
    }
}

fn api_error_redirect_parts(error: AuthError) -> AuthResult<(String, Option<String>)> {
    if !error.is_api_error()? {
        return Err(error);
    }
    let body = error.body_value()?;
    if body.is_null() || body.is_undefined() || !body.model_property("code")?.is_truthy() {
        return Err(error);
    }
    let code = error.body_value()?.model_property("code")?;
    let message = error.body_value()?.model_property("message")?;
    // URLSearchParams converts JavaScript strings to USVString at the URL boundary.
    let code = String::from_utf16_lossy(code.display_utf16()?.as_utf16());
    let description = message
        .is_truthy()
        .then(|| message.display_utf16())
        .transpose()?;
    Ok((
        code,
        description.map(|message| String::from_utf16_lossy(message.as_utf16())),
    ))
}

impl From<AuthError> for OAuthSignInError {
    fn from(error: AuthError) -> Self {
        Self::Auth(error)
    }
}

impl From<String> for OAuthSignInError {
    fn from(value: String) -> Self {
        Self::Generic(value)
    }
}

impl From<SessionIssueError> for OAuthSignInError {
    fn from(value: SessionIssueError) -> Self {
        match value {
            SessionIssueError::Auth(error) => Self::Auth(error),
            SessionIssueError::Banned { message } => Self::Banned(message),
        }
    }
}

fn api_error_or(
    error: AuthError,
    fallback: impl FnOnce(AuthError) -> OAuthSignInError,
) -> OAuthSignInError {
    match error.is_api_error() {
        Ok(true) => OAuthSignInError::Auth(error),
        Ok(false) => fallback(error),
        Err(error) => OAuthSignInError::Auth(error),
    }
}

fn account_query_error(
    error: AuthError,
    request: &AuthRequest,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
) -> OAuthSignInError {
    ctx.logger().error(
        "Better auth was unable to query your database.\nError: ",
        &[better_auth_core::observability::logger::LogArgument::Error(
            &error,
        )],
    );
    let target = ctx
        .config
        .api_error
        .error_url
        .clone()
        .filter(|url| !url.is_empty())
        .unwrap_or_else(|| format!("{}/error", super::handlers::auth_base_url(ctx)));
    let location =
        better_auth_core::utils::url::append_query_params(&target, "error=internal_server_error");
    OAuthSignInError::Auth(
        match location.and_then(|location| request.redirect(location)) {
            Ok(error) | Err(error) => error,
        },
    )
}

pub(super) async fn process_oauth_sign_in(
    provider_name: &str,
    provider: &ResolvedProvider,
    user_info: &FieldValue,
    account: &better_auth_core::FieldMap,
    options: OAuthSignInOptions<'_>,
    meta: &better_auth_core::RequestMeta,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
) -> Result<ProcessOAuthUserResult, OAuthSignInError> {
    let provider_id = account.get("providerId").cloned().unwrap_or_default();
    let account_id = account.get("accountId").cloned().unwrap_or_default();
    let require_email_verification = if provider_id.strict_equals(&provider_name.into()) {
        provider.config.require_email_verification.unwrap_or(false)
    } else {
        ctx.extensions
            .get::<std::sync::Arc<super::resolved::ResolvedOAuthConfig>>()
            .and_then(|config| {
                config
                    .providers
                    .iter()
                    .find(|(name, _)| provider_id.strict_equals(&name.as_str().into()))
            })
            .is_some_and(|(_, provider)| {
                provider.config.require_email_verification.unwrap_or(false)
            })
    };
    let account_owner = ctx
        .database
        .get_account_owner_value(&provider_id, &account_id)
        .await
        .map_err(|error| account_query_error(error, options.request, ctx))?;

    let mut endpoint = crate::plugins::endpoint_context::EndpointContext::new(
        Some(options.request),
        better_auth_core::FieldValue::from_json(options.body.clone())?,
        ctx,
    );
    endpoint.path = Some(callback_path(options.request));
    endpoint.session = options.request.native_session_snapshot()?;
    let (account_owner, existing_user) = match account_owner {
        Some(owner) => (Some(owner), None),
        None => {
            let existing = async {
                let email = super::native_user::lowercase(&lower_email(user_info)?, "email")?;
                ctx.database.get_user_with_accounts_value(&email).await
            }
            .await
            .map_err(|error| {
                api_error_or(error, |error| {
                    account_query_error(error, options.request, ctx)
                })
            })?;
            match existing {
                Some(existing) => {
                    let better_auth_core::store::JoinValue::Many(accounts) = existing.accounts
                    else {
                        return Err(AuthError::internal("accounts.find is not a function").into());
                    };
                    match accounts.into_iter().find(|account| {
                        account
                            .provider_id
                            .field_value()
                            .strict_equals(&provider_id)
                            && account.account_id.field_value().strict_equals(&account_id)
                    }) {
                        Some(account) => (
                            Some(better_auth_core::store::AccountOwner {
                                account,
                                user: better_auth_core::store::JoinValue::One(Some(existing.user)),
                            }),
                            None,
                        ),
                        None => (None, Some(existing.user)),
                    }
                }
                None => (None, None),
            }
        }
    };
    if let Some(owner) = account_owner {
        let user_id = match &owner.user {
            better_auth_core::store::JoinValue::One(Some(user)) => user.id().field_value(),
            better_auth_core::store::JoinValue::Many(_) => better_auth_core::FieldValue::Undefined,
            better_auth_core::store::JoinValue::One(None) => {
                return Err(OAuthSignInError::Generic("unable to link account".into()));
            }
        };
        let existing_account = owner.account;
        validate_provider_user(
            user_info,
            user_id,
            &provider_name.into(),
            options.profile,
            crate::plugins::user_admission::UserValidationAction::SignIn,
            &endpoint,
        )
        .await?;
        let token_update = if ctx.config.account.update_account_on_sign_in() {
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
            let mut fresh_tokens = better_auth_core::FieldMap::from([
                ("providerId".into(), provider_id.clone()),
                ("idToken".into(), token_bundle.id_token.field_value()),
                (
                    "accessToken".into(),
                    token_bundle.access_token.field_value(),
                ),
                (
                    "refreshToken".into(),
                    token_bundle.refresh_token.field_value(),
                ),
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
            ]);
            fresh_tokens.retain(|_, value| !value.is_undefined());
            Some(UpdateAccount {
                additional_fields: fresh_tokens,
                ..Default::default()
            })
        } else {
            None
        };
        if ctx.config.account.store_account_cookie() {
            let mut cookie_fields = existing_account.internal_fields()?;
            if let Some(update) = &token_update {
                cookie_fields.extend(update.fields()?);
            }
            options.set_account_cookie(
                Some(&AccountCookiePayload::from_adapter_fields(cookie_fields)),
                ctx,
            )?;
        }
        if let Some(update) = token_update {
            let _ = ctx
                .database
                .update_account_by_id_value(&existing_account.id.field_value(), update)
                .await?
                .ok_or_else(|| OAuthSignInError::Generic("unable to update account".to_owned()))?;
        }

        let mut owner_user = owner.user;
        if let better_auth_core::store::JoinValue::One(Some(user)) = &owner_user
            && user_info.model_property("emailVerified")?.is_truthy()
            && !user.email_verified().is_truthy()?
            && user
                .email()
                .field_value()
                .strict_equals(&lower_email(user_info)?)
        {
            let _ = ctx
                .database
                .update_user_by_id_value(
                    &user.id().field_value(),
                    UpdateUser {
                        email_verified: Some(true),
                        ..Default::default()
                    },
                )
                .await?;
        }
        if options.override_user_info {
            let existing = match &owner_user {
                better_auth_core::store::JoinValue::One(Some(user)) => Some(user),
                _ => None,
            };
            let (id, update) = provider_profile_update(ctx, user_info, existing)?;
            let updated = ctx.database.update_user_by_id_value(&id, update).await?;
            if let Some(user) = updated {
                owner_user = better_auth_core::store::JoinValue::One(Some(user));
            } else {
                better_auth_core::observability::logger::current().warn(
                    "Could not update user info during OAuth sign in; preserving existing user for session.",
                    &[],
                );
            }
        }
        let user = match owner_user {
            better_auth_core::store::JoinValue::One(Some(user)) => {
                options
                    .check_email_verification(require_email_verification, Some(&user), false, ctx)
                    .await?;
                better_auth_core::FieldValue::from(better_auth_core::FieldMap::from(user))
            }
            better_auth_core::store::JoinValue::Many(users) => {
                options
                    .check_email_verification(require_email_verification, None, false, ctx)
                    .await?;
                better_auth_core::FieldValue::Array(
                    users
                        .into_iter()
                        .map(|user| better_auth_core::FieldMap::from(user).into())
                        .collect(),
                )
            }
            better_auth_core::store::JoinValue::One(None) => {
                return Err(OAuthSignInError::Generic("unable to link account".into()));
            }
        };
        let issued =
            issue_selected_user_session_optional(ctx, user, meta, ctx.config.session.expires_in())
                .await
                .map_err(OAuthSignInError::from)?
                .ok_or_else(|| OAuthSignInError::Generic("unable to create session".into()))?;
        return Ok(ProcessOAuthUserResult {
            issued,
            is_register: false,
        });
    }

    if let Some(existing_user) = existing_user {
        let linking = &ctx.config.account.account_linking;
        let trusted_provider = ctx
            .trusted_providers()
            .iter()
            .any(|trusted| provider_id.strict_equals(&trusted.as_str().into()));

        // Mirrors upstream's linking guard, including the local-account check:
        // an unverified local account is not implicitly linkable.
        if !linking.enabled()
            || linking.disable_implicit_linking
            || (!trusted_provider && !user_info.model_property("emailVerified")?.is_truthy())
            || (linking.require_local_email_verified
                && !existing_user.email_verified().is_truthy()?)
        {
            return Err(OAuthSignInError::Generic("account not linked".to_string()));
        }

        let _ = async {
            validate_provider_user(
                user_info,
                existing_user.id().field_value(),
                &provider_name.into(),
                options.profile,
                crate::plugins::user_admission::UserValidationAction::LinkAccount,
                &endpoint,
            )
            .await?;
            let account = oauth_account_input(ctx, account)?;
            let created_account = ctx
                .database
                .create_account_optional(CreateAccount {
                    field_order: [
                        "providerId",
                        "accountId",
                        "userId",
                        "accessToken",
                        "refreshToken",
                        "idToken",
                        "accessTokenExpiresAt",
                        "refreshTokenExpiresAt",
                        "scope",
                    ]
                    .into_iter()
                    .map(str::to_owned)
                    .collect(),
                    user_id: existing_user.id().into_owned(),
                    ..account
                })
                .await?;
            if let Some(account) = &created_account {
                options.set_account_cookie(Some(account), ctx)?;
            }
            Ok::<_, AuthError>(created_account)
        }
        .await
        .map_err(|error| {
            api_error_or(error, |error| {
                ctx.logger().error(
                    "Unable to link account",
                    &[better_auth_core::observability::LogArgument::Error(&error)],
                );
                OAuthSignInError::Generic("unable to link account".to_owned())
            })
        })?
        .ok_or_else(|| OAuthSignInError::Generic("unable to link account".to_owned()))?;

        if user_info.model_property("emailVerified")?.is_truthy()
            && !existing_user.email_verified().is_truthy()?
            && existing_user
                .email()
                .field_value()
                .strict_equals(&lower_email(user_info)?)
        {
            let _ = ctx
                .database
                .update_user_by_id_value(
                    &existing_user.id().field_value(),
                    UpdateUser {
                        email_verified: Some(true),
                        ..Default::default()
                    },
                )
                .await?;
        }

        let mut linked_user = super::handlers::apply_link_user_info(
            &existing_user.id().field_value(),
            user_info,
            ctx,
        )
        .await
        .unwrap_or_else(|| existing_user.clone());
        if options.override_user_info {
            let (id, update) = provider_profile_update(ctx, user_info, Some(&existing_user))?;
            let updated = ctx.database.update_user_by_id_value(&id, update).await?;
            if let Some(user) = updated {
                linked_user = user;
            } else {
                better_auth_core::observability::logger::current().warn(
                    "Could not update user info during OAuth sign in; preserving existing user for session.",
                    &[],
                );
            }
        }

        options
            .check_email_verification(require_email_verification, Some(&linked_user), false, ctx)
            .await?;
        let issued = issue_selected_user_session_optional(
            ctx,
            better_auth_core::FieldMap::from(linked_user).into(),
            meta,
            ctx.config.session.expires_in(),
        )
        .await
        .map_err(OAuthSignInError::from)?
        .ok_or_else(|| OAuthSignInError::Generic("unable to create session".into()))?;
        Ok(ProcessOAuthUserResult {
            issued,
            is_register: false,
        })
    } else {
        if options.disable_sign_up {
            return Err(OAuthSignInError::Generic("signup disabled".to_string()));
        }

        let created_user = async {
            let fields = provider_profile_fields(ctx, user_info, true)?;
            let account = oauth_account_input(ctx, account)?;
            let user_info = user_info.clone();

            let context = ctx.clone();
            let request = options.request.clone();
            let admission_body = options.body.clone();
            let admission_session = endpoint.session;
            let source = crate::plugins::user_admission::UserValidationSource::oauth(
                &provider_name.into(),
                options.profile,
                crate::plugins::user_admission::UserValidationAction::CreateUser,
            );
            let (created_user, created_account) =
                better_auth_core::store::transaction(ctx.database.as_ref(), move |tx| {
                    Box::pin(async move {
                        let mut endpoint = crate::plugins::endpoint_context::EndpointContext::new(
                            Some(&request),
                            better_auth_core::FieldValue::from_json(admission_body)?,
                            &context,
                        );
                        endpoint.path = Some(callback_path(&request));
                        endpoint.session = admission_session;
                        endpoint.transaction = Some(tx);
                        let mut fields = fields;
                        fields.extend([
                            ("email".into(), lower_email(&user_info)?),
                            (
                                "emailVerified".into(),
                                user_info.model_property("emailVerified")?,
                            ),
                        ]);
                        let mut create_user = CreateUser {
                            additional_fields: fields,
                            ..Default::default()
                        }
                        .into_user_fields()?;
                        if let Err(error) = crate::plugins::user_admission::validate_create(
                            &create_user,
                            source,
                            &endpoint,
                        )
                        .await
                        {
                            return Err(error.into_auth_error());
                        }
                        apply_default_role(&context, &mut create_user);
                        let user = tx
                            .create_user_fields_optional(create_user)
                            .await?
                            .ok_or_else(|| {
                                AuthError::internal("Cannot read properties of null (reading 'id')")
                            })?;
                        let mut account = account;
                        account.field_order = account.fields()?.keys().cloned().collect();
                        account.field_order.push("userId".into());
                        account.user_id = user.id().into_owned();
                        let created_account = tx.create_account_optional(account).await?;
                        Ok((user, created_account))
                    })
                })
                .await?;
            options.set_account_cookie(created_account.as_ref(), ctx)?;
            Ok::<_, AuthError>(created_user)
        }
        .await
        .map_err(|error| {
            api_error_or(error, |error| {
                ctx.logger().error(
                    "Unable to create OAuth user",
                    &[better_auth_core::observability::LogArgument::Error(&error)],
                );
                OAuthSignInError::Generic("unable to create user".to_owned())
            })
        })?;
        options
            .check_email_verification(require_email_verification, Some(&created_user), true, ctx)
            .await?;
        let issued = issue_selected_user_session_optional(
            ctx,
            better_auth_core::FieldMap::from(ctx.internal_user_view(&created_user).await?).into(),
            meta,
            ctx.config.session.expires_in(),
        )
        .await
        .map_err(OAuthSignInError::from)?
        .ok_or_else(|| OAuthSignInError::Generic("unable to create session".into()))?;
        Ok(ProcessOAuthUserResult {
            issued,
            is_register: true,
        })
    }
}

pub(super) fn token_account(
    provider_name: &str,
    account_id: &FieldValue,
    tokens: &FieldValue,
) -> AuthResult<better_auth_core::FieldMap> {
    let mut account = better_auth_core::FieldMap::from([
        ("providerId".into(), provider_name.into()),
        ("accountId".into(), account_id.clone()),
    ]);
    account.extend(tokens.enumerable_fields()?);
    let _ = account.insert(
        "scope".into(),
        super::providers::joined_scopes(&tokens.model_property("scopes")?)?,
    );
    Ok(account)
}

fn oauth_account_input(
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
    account: &better_auth_core::FieldMap,
) -> AuthResult<CreateAccount> {
    let tokens_to_store = encrypt_token_set(
        ctx,
        better_auth_core::SchemaValue::Dynamic(
            account.get("accessToken").cloned().unwrap_or_default(),
        ),
        better_auth_core::SchemaValue::Dynamic(
            account.get("refreshToken").cloned().unwrap_or_default(),
        ),
        better_auth_core::SchemaValue::Dynamic(account.get("idToken").cloned().unwrap_or_default()),
    )?;
    Ok(CreateAccount {
        additional_fields: better_auth_core::FieldMap::from([
            (
                "accessToken".into(),
                tokens_to_store.access_token.into_field_value(),
            ),
            (
                "refreshToken".into(),
                tokens_to_store.refresh_token.into_field_value(),
            ),
            (
                "idToken".into(),
                tokens_to_store.id_token.into_field_value(),
            ),
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
                account.get("scope").cloned().unwrap_or_default(),
            ),
            (
                "providerId".into(),
                account.get("providerId").cloned().unwrap_or_default(),
            ),
            (
                "accountId".into(),
                account.get("accountId").cloned().unwrap_or_default(),
            ),
        ]),
        ..Default::default()
    })
}

fn provider_profile_update<S: better_auth_core::AuthSchema>(
    ctx: &AuthContext<S>,
    user_info: &FieldValue,
    existing: Option<&UserView>,
) -> AuthResult<(FieldValue, UpdateUser)> {
    let mut fields = provider_profile_fields(ctx, user_info, false)?;
    let id = existing
        .map(|user| user.id().field_value())
        .unwrap_or_default();
    let _ = fields.insert("email".into(), lower_email(user_info)?);
    let same_email = lower_email(user_info)?.strict_equals(
        &existing
            .map(|user| user.email().field_value())
            .unwrap_or_default(),
    );
    let verified = if same_email {
        existing
            .map(|user| user.email_verified().field_value())
            .unwrap_or_default()
    } else {
        FieldValue::Undefined
    };
    let _ = fields.insert(
        "emailVerified".into(),
        if same_email && verified.is_truthy() {
            verified
        } else {
            user_info.model_property("emailVerified")?
        },
    );
    Ok((
        id,
        UpdateUser {
            additional_fields: fields,
            ..Default::default()
        },
    ))
}

pub(super) fn provider_profile_fields(
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
    user_info: &FieldValue,
    create: bool,
) -> AuthResult<better_auth_core::FieldMap> {
    let (name, image, profile) = super::native_user::profile_fields(user_info, true)?;
    let additional = ctx.config.user.parse_provider_input(&profile, create)?;
    let mut fields =
        better_auth_core::FieldMap::from([("name".into(), name), ("image".into(), image)]);
    fields.extend(additional);
    Ok(fields)
}

pub(crate) async fn sign_in_verified_profile(
    provider_name: &str,
    provider: &super::providers::OAuthProvider,
    user: super::providers::OAuthUserInfoResponse,
    tokens: OAuthTokenSet,
    disable_sign_up: bool,
    req: &AuthRequest,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
) -> AuthResult<AuthResponse> {
    let resolved = ResolvedProvider {
        config: provider.clone(),
        generic: None,
    };
    let account_id: FieldValue = user.user.id.clone().into();
    let info = user.into_native();
    let profile = info.model_property("data")?;
    let user = info.model_property("user")?;
    let outcome = process_oauth_sign_in(
        provider_name,
        &resolved,
        &user,
        &token_account(provider_name, &account_id, &tokens.fields().into())?,
        OAuthSignInOptions {
            request: req,
            profile: Some(&profile),
            body: req.body_as_json()?,
            disable_sign_up,
            override_user_info: false,
            callback_url: "/",
            email_verification: None,
        },
        &better_auth_core::RequestMeta::from_request_with_config(
            req,
            &ctx.config.advanced.ip_address,
        ),
        ctx,
    )
    .await
    .map_err(|error| match error {
        OAuthSignInError::Auth(error) => error,
        OAuthSignInError::Generic(message) if message == "email_not_verified" => {
            AuthError::from_code("FORBIDDEN", "EMAIL_NOT_VERIFIED", "Email not verified")
        }
        OAuthSignInError::Generic(message) => AuthError::authentication_failed(message),
        OAuthSignInError::Banned(message) => AuthError::banned_user(message),
    })?;
    ctx.session_manager()
        .set_native_session_cookie(req, outcome.issued.clone(), None)
        .await?;
    Ok(AuthResponse::native(
        None,
        better_auth_core::FieldMap::from([
            ("token".into(), outcome.issued.session.token().field_value()),
            ("user".into(), outcome.issued.public_user(&ctx.config.user)?),
        ])
        .into(),
    ))
}

pub(super) async fn validate_provider_user<S: better_auth_core::AuthSchema>(
    user: &FieldValue,
    user_id: better_auth_core::FieldValue,
    provider: &better_auth_core::FieldValue,
    profile: Option<&FieldValue>,
    action: crate::plugins::user_admission::UserValidationAction,
    endpoint: &crate::plugins::endpoint_context::EndpointContext<'_, S>,
) -> AuthResult<()> {
    let _ = user.model_property("id")?;
    let mut fields = user.enumerable_fields_except(&["id"])?;
    let _ = fields.insert("id".into(), user_id);
    let _ = fields.insert("email".into(), lower_email(user)?);
    crate::plugins::user_admission::validate(
        crate::plugins::user_admission::UserValidationData {
            user: fields,
            source: crate::plugins::user_admission::UserValidationSource::oauth(
                provider, profile, action,
            ),
        },
        endpoint,
    )
    .await
    .map_err(crate::plugins::user_admission::UserValidationRejection::into_auth_error)
}

pub(super) fn callback_path(request: &AuthRequest) -> &str {
    if request.path().starts_with("/callback/") {
        "/callback/:id"
    } else if request.path().starts_with("/oauth2/callback/") {
        "/oauth2/callback/:providerId"
    } else {
        request.path()
    }
}

#[cfg(test)]
#[path = "signin_override_tests.rs"]
mod override_tests;

#[cfg(test)]
#[path = "signin_error_tests.rs"]
mod error_tests;

#[cfg(test)]
#[path = "signin_flow_tests.rs"]
mod flow_tests;
