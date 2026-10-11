use better_auth_core::SchemaValue;
use better_auth_core::{
    AuthContext, AuthError, AuthRequest, AuthResponse, AuthResult, FieldMap, FieldValue,
    UpdateAccount,
};
use chrono::Utc;

use super::encryption::encrypt_value;
use super::handlers::{
    create_account_cookie_headers, decode_account_cookie, fetch_user_info_from_provider,
    refresh_tokens_via_provider,
};
use super::providers::{OAuthTokenSet, OAuthUserInfoRequest};
use super::resolved::ResolvedOAuthConfig as OAuthConfig;
use super::state::AccountCookiePayload;
use super::types::{
    AccessTokenResponse, AccountInfoAccount, AccountInfoResponse, AccountInfoUser,
    RefreshTokenResponse,
};

#[derive(Clone)]
enum AccountSource {
    Id(String),
    Cookie,
}

#[derive(Clone)]
struct AccountSelection {
    source: AccountSource,
    user_id: Option<String>,
}

pub(super) fn account_body(
    req: &AuthRequest,
) -> AuthResult<better_auth_core::endpoint_input::ValidatedBody> {
    let projection = req.input_body()?;
    let selection =
        AccountSelection::from_value(projection.clone().unwrap_or(serde_json::Value::Null))
            .map_err(|message| {
                crate::plugins::json_body::validation_error(&format!("[body] {message}"))
            })?;
    Ok(better_auth_core::endpoint_input::ValidatedBody::new(
        projection, selection,
    ))
}

fn invalid_selection(location: &str, message: String) -> AuthResult<AuthResponse> {
    Err(AuthError::FieldInput {
        code: "VALIDATION_ERROR",
        message: format!("[{location}] {message}"),
    })
}

impl AccountSelection {
    fn from_body(req: &AuthRequest) -> Result<Self, String> {
        if let Some(selection) = req.validated_body::<Self>() {
            return Ok(selection.clone());
        }
        let value = req.body_as_json().map_err(|_| "Invalid input".to_owned())?;
        Self::from_value(value)
    }

    fn from_query(req: &AuthRequest) -> Result<Self, String> {
        Self::from_value(req.query.clone().unwrap_or(serde_json::Value::Null))
    }

    fn from_value(value: serde_json::Value) -> Result<Self, String> {
        let object = value
            .as_object()
            .ok_or_else(|| "Invalid input".to_owned())?;
        if object.get("userId").is_some_and(|value| !value.is_string()) {
            return Err("Invalid input".into());
        }
        let account_id = object.get("accountId").and_then(serde_json::Value::as_str);
        let use_cookie = object
            .get("useAccountCookie")
            .and_then(serde_json::Value::as_bool)
            == Some(true);
        let (selection, field) = match (account_id, use_cookie) {
            (Some(id), false) => (AccountSource::Id(id.to_owned()), "accountId"),
            (None, true) => (AccountSource::Cookie, "useAccountCookie"),
            _ => return Err("Invalid input".into()),
        };
        let unknown: Vec<_> = object
            .keys()
            .filter(|key| key.as_str() != field && key.as_str() != "userId")
            .collect();
        if !unknown.is_empty() {
            let suffix = if unknown.len() == 1 { "" } else { "s" };
            let names = unknown
                .into_iter()
                .map(|key| serde_json::Value::String(key.clone()).to_string())
                .collect::<Vec<_>>()
                .join(", ");
            return Err(format!("Unrecognized key{suffix}: {names}"));
        }
        Ok(Self {
            source: selection,
            user_id: object
                .get("userId")
                .and_then(serde_json::Value::as_str)
                .map(str::to_owned),
        })
    }

    async fn resolve_user_id(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<impl better_auth_core::AuthSchema>,
    ) -> AuthResult<FieldValue> {
        let read = if ctx.store_capabilities().server_sessions() {
            better_auth_core::session::SessionRead::CookieBypass
        } else {
            better_auth_core::session::SessionRead::Cached
        };
        let session = ctx.native_session(req, read).await?;
        let endpoint = crate::plugins::endpoint_context::EndpointContext::new(
            Some(req),
            FieldValue::Undefined,
            ctx,
        );
        if session.is_none() && (endpoint.request.is_some() || endpoint.headers().is_some()) {
            return Err(AuthError::Unauthenticated);
        }
        session
            .as_ref()
            .map(|data| data.user_field("id"))
            .transpose()?
            .filter(FieldValue::is_truthy)
            .or_else(|| {
                self.user_id
                    .as_deref()
                    .map(FieldValue::from)
                    .filter(FieldValue::is_truthy)
            })
            .ok_or(AuthError::Upstream {
                status: 400,
                code: "USER_ID_OR_SESSION_REQUIRED",
                message: "Either userId or session is required",
            })
    }

    fn matches(
        &self,
        account: &AccountCookiePayload,
        user_id: &FieldValue,
        ctx: &AuthContext<impl better_auth_core::AuthSchema>,
    ) -> bool {
        (!ctx.store_capabilities().database || account.user_id.field_value().strict_equals(user_id))
            && match &self.source {
                AccountSource::Id(id) => {
                    account.id.field_value().strict_equals(&id.as_str().into())
                }
                AccountSource::Cookie => true,
            }
    }

    async fn resolve(
        &self,
        req: &AuthRequest,
        user_id: &FieldValue,
        ctx: &AuthContext<impl better_auth_core::AuthSchema>,
    ) -> AuthResult<AccountCookiePayload> {
        let account = match &self.source {
            AccountSource::Id(account_id) => ctx
                .database
                .get_user_accounts_value(user_id)
                .await?
                .iter()
                .find(|account| {
                    account
                        .id
                        .field_value()
                        .strict_equals(&account_id.as_str().into())
                })
                .cloned(),
            AccountSource::Cookie if ctx.config.account.store_account_cookie() => {
                decode_account_cookie(req, &ctx.config)?
                    .filter(|account| self.matches(account, user_id, ctx))
            }
            AccountSource::Cookie => None,
        };
        account.ok_or_else(|| AuthError::bad_request("Account not found"))
    }
}

fn provider_for<'a>(
    config: &'a OAuthConfig,
    account: &AccountCookiePayload,
) -> AuthResult<&'a super::resolved::ResolvedProvider> {
    if let Some((_, provider)) = config
        .providers
        .iter()
        .find(|(name, _)| account.provider_id == name.as_str())
    {
        return Ok(provider);
    }
    Err(AuthError::bad_request(format!(
        "Provider {} is not supported.",
        account.provider_id.display_string()?
    )))
}

fn parse_scopes(scope: &SchemaValue<Option<String>>) -> AuthResult<SchemaValue<Vec<String>>> {
    Ok(SchemaValue::Dynamic(
        super::providers::split_scopes(&scope.field_value())?.into(),
    ))
}

fn nullish<T: better_auth_core::SchemaField>(value: &SchemaValue<T>) -> bool {
    matches!(
        value.field_value(),
        FieldValue::Null | FieldValue::Undefined
    )
}

fn date_value(
    value: &SchemaValue<Option<better_auth_core::FieldDate>>,
) -> AuthResult<SchemaValue<better_auth_core::FieldDate>> {
    Ok(SchemaValue::from_field(value.field_value()))
}

fn decrypt_value(
    value: &SchemaValue<Option<String>>,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
) -> AuthResult<SchemaValue<Option<String>>> {
    super::encryption::decrypt_value(
        value,
        ctx.config.account.encrypt_oauth_tokens(),
        ctx.config.encryption_secret(),
    )
}

enum TokenRefresh {
    AccessToken,
    RefreshToken,
}

async fn persist_tokens(
    account: &AccountCookiePayload,
    tokens: &OAuthTokenSet,
    refresh: TokenRefresh,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
) -> AuthResult<AccountCookiePayload> {
    let encrypt = |value| {
        encrypt_value(
            value,
            ctx.config.account.encrypt_oauth_tokens(),
            ctx.config.encryption_secret(),
        )
    };
    let refresh_token = || -> AuthResult<FieldValue> {
        if tokens.refresh_token.is_truthy()? {
            Ok(encrypt(tokens.refresh_token.clone())?.into_field_value())
        } else {
            Ok(account.refresh_token.field_value())
        }
    };
    let (access_token, refresh_token) = match refresh {
        TokenRefresh::AccessToken => (
            encrypt(tokens.access_token.clone())?.into_field_value(),
            refresh_token()?,
        ),
        TokenRefresh::RefreshToken => {
            let refresh_token = refresh_token()?;
            (
                encrypt(tokens.access_token.clone())?.into_field_value(),
                refresh_token,
            )
        }
    };
    let access_token_expires_at = tokens.access_token_expires_at.field_value();
    // The endpoints construct these properties in different observable hook orders.
    let middle = match refresh {
        TokenRefresh::AccessToken => [
            ("accessTokenExpiresAt", access_token_expires_at),
            ("refreshToken", refresh_token),
        ],
        TokenRefresh::RefreshToken => [
            ("refreshToken", refresh_token),
            ("accessTokenExpiresAt", access_token_expires_at),
        ],
    };
    let update_fields: FieldMap = std::iter::once(("accessToken", access_token))
        .chain(middle)
        .chain([
            (
                "refreshTokenExpiresAt",
                if nullish(&tokens.refresh_token_expires_at) {
                    account.refresh_token_expires_at.field_value()
                } else {
                    tokens.refresh_token_expires_at.field_value()
                },
            ),
            (
                "idToken",
                if tokens.id_token.is_truthy()? {
                    tokens.id_token.field_value()
                } else {
                    account.id_token.field_value()
                },
            ),
        ])
        .map(|(name, value)| (name.into(), value))
        .collect();
    let updated = if account.id.is_truthy()? {
        ctx.database
            .update_account_by_id_value(
                &account.id.field_value(),
                UpdateAccount {
                    additional_fields: update_fields.clone(),
                    ..Default::default()
                },
            )
            .await?
    } else {
        None
    };
    Ok(updated.unwrap_or_else(|| AccountCookiePayload::from_adapter_fields(update_fields)))
}

fn set_refreshed_account_cookie(
    req: &AuthRequest,
    config: &better_auth_core::AuthConfig,
    account: &AccountCookiePayload,
    update: &AccountCookiePayload,
) -> AuthResult<()> {
    let mut fields = account.internal_fields()?;
    fields.extend(update.internal_fields()?);
    let cookie = AccountCookiePayload::from_adapter_fields(fields);
    for header in create_account_cookie_headers(req, config, &cookie)? {
        req.append_response_header("Set-Cookie", header)?;
    }
    Ok(())
}

async fn valid_access_token(
    account: &AccountCookiePayload,
    selection: &AccountSelection,
    user_id: &FieldValue,
    config: &OAuthConfig,
    req: &AuthRequest,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
) -> AuthResult<AccessTokenResponse> {
    if !selection.matches(account, user_id, ctx) {
        return Err(AuthError::bad_request("Account not found"));
    }
    let provider = provider_for(config, account)?;
    async {
        let expired = account.access_token_expires_at.is_truthy()?
            && date_value(&account.access_token_expires_at)?
                .converted_date()?
                .is_before(Utc::now() + chrono::Duration::seconds(5))?;
        let new_tokens = if expired
            && account.refresh_token.is_truthy()?
            && provider.config.supports_refresh()
        {
            let value = decrypt_value(&account.refresh_token, ctx)?;
            let tokens = refresh_tokens_via_provider(provider, &value.field_value(), req).await?;
            let updated = persist_tokens(account, &tokens, TokenRefresh::AccessToken, ctx).await?;
            if ctx.config.account.store_account_cookie() {
                set_refreshed_account_cookie(req, &ctx.config, account, &updated)?;
            }
            Some(tokens)
        } else {
            None
        };
        let access_token = match new_tokens
            .as_ref()
            .map(|tokens| &tokens.access_token)
            .filter(|value| !nullish(value))
        {
            Some(token) => token.clone(),
            None => {
                let value = if nullish(&account.access_token) {
                    Some(String::new()).into()
                } else {
                    account.access_token.clone()
                };
                decrypt_value(&value, ctx)?
            }
        };
        let fresh_expiry = new_tokens
            .as_ref()
            .map(|tokens| &tokens.access_token_expires_at);
        let expiry = match fresh_expiry {
            Some(value) if value.is_truthy()? => value,
            _ => &account.access_token_expires_at,
        };
        let access_token_expires_at = if expiry.is_truthy()? {
            if expiry.field_value().is_string() {
                date_value(expiry)?.converted_date()?.map(Some)
            } else {
                expiry.clone()
            }
        } else {
            SchemaValue::Undefined
        };
        let id_token = new_tokens
            .as_ref()
            .map(|tokens| &tokens.id_token)
            .filter(|value| !nullish(value))
            .cloned()
            .unwrap_or_else(|| {
                if nullish(&account.id_token) {
                    SchemaValue::Undefined
                } else {
                    account.id_token.clone()
                }
            });
        Ok(AccessTokenResponse {
            access_token,
            access_token_expires_at,
            scopes: parse_scopes(&account.scope)?,
            id_token,
        })
    }
    .await
    .map_err(|_: AuthError| AuthError::bad_request("Failed to get a valid access token"))
}

pub(super) async fn handle_get_access_token(
    config: &OAuthConfig,
    req: &AuthRequest,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
) -> AuthResult<AuthResponse> {
    let selection = match AccountSelection::from_body(req) {
        Ok(selection) => selection,
        Err(message) => return invalid_selection("body", message),
    };
    let user_id = selection.resolve_user_id(req, ctx).await?;
    let account = selection.resolve(req, &user_id, ctx).await?;
    let response = valid_access_token(&account, &selection, &user_id, config, req, ctx).await?;
    Ok(AuthResponse::native(None, response.into_field_value()))
}

pub(super) async fn handle_refresh_token(
    config: &OAuthConfig,
    req: &AuthRequest,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
) -> AuthResult<AuthResponse> {
    let selection = match AccountSelection::from_body(req) {
        Ok(selection) => selection,
        Err(message) => return invalid_selection("body", message),
    };
    let user_id = selection.resolve_user_id(req, ctx).await?;
    let account = selection.resolve(req, &user_id, ctx).await?;
    let provider = provider_for(config, &account)?;
    if !provider.config.supports_refresh() {
        return Err(AuthResponse::json(
            400,
            &serde_json::json!({
                "code": "TOKEN_REFRESH_NOT_SUPPORTED",
                "message": format!(
                    "Provider {} does not support token refreshing.",
                    account.provider_id.display_string()?
                ),
            }),
        )?
        .into());
    }
    if !account.refresh_token.is_truthy()? {
        return Err(AuthError::bad_request("Refresh token not found"));
    }
    async {
        let decrypted = decrypt_value(&account.refresh_token, ctx)?;
        let tokens = refresh_tokens_via_provider(provider, &decrypted.field_value(), req).await?;
        let updated = persist_tokens(&account, &tokens, TokenRefresh::RefreshToken, ctx).await?;
        if matches!(selection.source, AccountSource::Cookie)
            && ctx.config.account.store_account_cookie()
        {
            set_refreshed_account_cookie(req, &ctx.config, &account, &updated)?;
        }
        let response = RefreshTokenResponse {
            access_token: tokens.access_token.clone(),
            access_token_expires_at: tokens.access_token_expires_at.clone(),
            refresh_token: if nullish(&tokens.refresh_token) {
                decrypted
            } else {
                tokens.refresh_token.clone()
            },
            refresh_token_expires_at: if nullish(&tokens.refresh_token_expires_at) {
                account.refresh_token_expires_at.clone()
            } else {
                tokens.refresh_token_expires_at.clone()
            },
            scope: if nullish(&updated.scope) {
                account.scope.clone()
            } else {
                updated.scope.clone()
            },
            id_token: if tokens.id_token.is_truthy()? {
                tokens.id_token
            } else {
                account.id_token.clone()
            },
            provider_id: account.provider_id.clone(),
            account_id: account.id.clone(),
        };
        Ok(AuthResponse::native(None, response.into_field_value()))
    }
    .await
    .map_err(|_: AuthError| AuthError::bad_request("Failed to refresh access token"))
}

pub(super) async fn handle_account_info(
    config: &OAuthConfig,
    req: &AuthRequest,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
) -> AuthResult<AuthResponse> {
    let selection = match AccountSelection::from_query(req) {
        Ok(selection) => selection,
        Err(message) => return invalid_selection("query", message),
    };
    let user_id = selection.resolve_user_id(req, ctx).await?;
    let account = selection.resolve(req, &user_id, ctx).await?;
    let provider = config
        .providers
        .iter()
        .find(|(name, _)| account.provider_id == name.as_str())
        .map(|(_, provider)| provider)
        .ok_or(AuthError::Upstream {
            status: 400,
            code: "PROVIDER_NOT_CONFIGURED",
            message: "Account is not associated with a configured social provider.",
        })?;
    let tokens = valid_access_token(&account, &selection, &user_id, config, req, ctx).await?;
    if !tokens.access_token.is_truthy()? {
        return Err(AuthError::bad_request("Access token not found"));
    }
    let request = OAuthUserInfoRequest::from_fields(tokens.into_field_value().enumerable_fields()?);
    let (user, data) = if let Some(generic) = &provider.generic {
        let info = super::generic_profile::fetch_profile(generic, &request, None, None)
            .await
            .map_err(super::generic_profile::GenericProfileError::into_auth_error)?
            .ok_or_else(super::social_profile::missing_profile)?;
        (info.user, info.data)
    } else {
        let info = fetch_user_info_from_provider(provider, request, None)
            .await?
            .ok_or_else(super::social_profile::missing_profile)?;
        (
            AccountInfoUser {
                id: provider
                    .config
                    .account_info_includes_id()
                    .then_some(info.user.id),
                name: info.user.name,
                email: info.user.email,
                image: info.user.image,
                email_verified: info.user.email_verified,
                additional_fields: info.user.additional_fields,
            },
            info.data,
        )
    };
    let response = AccountInfoResponse {
        user,
        data,
        account: AccountInfoAccount {
            id: account.id.clone(),
            provider_id: account.provider_id.clone(),
            account_id: account.account_id.clone(),
        },
    };
    Ok(AuthResponse::native(None, response.into_field_value()))
}
