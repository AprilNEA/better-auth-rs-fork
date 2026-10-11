use better_auth_core::{AuthError, AuthResult, FieldMap, FieldValue};
use serde_json::Value;

use super::{
    OAuthProvider, OAuthTokenSet, OAuthUserInfo, OAuthUserInfoRequest, OAuthUserInfoResponse,
};
use crate::plugins::oauth::provider_tokens::expiry_at;
use crate::plugins::oauth::social_profile::fetch_http_profile;
use crate::plugins::oauth::token::{TokenGrantType, TokenRequest};

pub(in crate::plugins::oauth) async fn exchange_code(
    provider: &OAuthProvider,
    code: &str,
) -> AuthResult<OAuthTokenSet> {
    let value = TokenRequest::send_query(
        &provider.token_url,
        &[
            ("appid", &provider.client_id),
            ("secret", &provider.client_secret),
            ("code", code),
            ("grant_type", "authorization_code"),
        ],
    )
    .await?;
    tokens(value, TokenGrantType::AuthorizationCode)
}

pub(in crate::plugins::oauth) async fn refresh_tokens(
    provider: &OAuthProvider,
    endpoint: &str,
    refresh_token: &str,
) -> AuthResult<OAuthTokenSet> {
    let value = TokenRequest::send_query(
        endpoint,
        &[
            ("appid", &provider.client_id),
            ("grant_type", "refresh_token"),
            ("refresh_token", refresh_token),
        ],
    )
    .await?;
    tokens(value, TokenGrantType::RefreshToken)
}

fn tokens(value: Value, grant: TokenGrantType) -> AuthResult<OAuthTokenSet> {
    if value.is_null() || provider_error(&value) {
        let operation = match grant {
            TokenGrantType::AuthorizationCode => "validate authorization code",
            TokenGrantType::RefreshToken => "refresh access token",
        };
        let message = value
            .get("errmsg")
            .and_then(Value::as_str)
            .filter(|message| !message.is_empty())
            .unwrap_or("Unknown error");
        return Err(AuthError::internal(format!(
            "Failed to {operation}: {message}"
        )));
    }
    let response = FieldValue::from_json(value)?;
    let expires_in =
        better_auth_core::query::field_number(&response.model_property("expires_in")?)?;
    let scope = response.model_property("scope")?;
    let scope = scope
        .as_str()
        .ok_or_else(|| AuthError::type_error("tokenData.scope.split is not a function"))?;
    let mut fields = FieldMap::from([
        ("tokenType".into(), "Bearer".into()),
        (
            "accessToken".into(),
            response.model_property("access_token")?,
        ),
        (
            "refreshToken".into(),
            response.model_property("refresh_token")?,
        ),
        (
            "accessTokenExpiresAt".into(),
            FieldValue::Date(expiry_at(expires_in)?),
        ),
        (
            "scopes".into(),
            scope
                .split(',')
                .map(FieldValue::from)
                .collect::<Vec<_>>()
                .into(),
        ),
    ]);
    if grant == TokenGrantType::AuthorizationCode {
        for name in ["openid", "unionid"] {
            let _ = fields.insert(name.into(), response.model_property(name)?);
        }
    }
    Ok(OAuthTokenSet::from_fields(fields))
}

fn provider_error(value: &Value) -> bool {
    value
        .get("errcode")
        .is_some_and(crate::plugins::json_body::is_truthy)
}

pub(in crate::plugins::oauth) async fn fetch_user_info(
    provider: &OAuthProvider,
    request: &OAuthUserInfoRequest,
) -> AuthResult<Option<OAuthUserInfoResponse>> {
    let openid = request
        .additional_fields
        .get("openid")
        .cloned()
        .unwrap_or_default();
    if !openid.is_truthy() {
        return Ok(None);
    }
    let endpoint = provider
        .user_info_url
        .as_deref()
        .ok_or_else(|| AuthError::internal("Missing user_info_url for provider"))?;
    let access_token = if request.access_token.is_truthy()? {
        super::token_http::form_string(&request.access_token.field_value())?
    } else {
        String::new()
    };
    let openid = super::token_http::form_string(&openid)?;
    let request = reqwest::Client::new().get(endpoint).query(&[
        ("access_token", access_token.as_str()),
        ("openid", openid.as_str()),
        ("lang", "zh_CN"),
    ]);
    let Some(data) = fetch_http_profile(request).await? else {
        return Ok(None);
    };
    if data.is_null() || provider_error(&data) {
        return Ok(None);
    }
    Ok(provider
        .decode_profile(data.clone())?
        .map(|user| OAuthUserInfoResponse { user, data }))
}

pub(super) fn decode_profile(profile: Value) -> Result<OAuthUserInfo, String> {
    Ok(OAuthUserInfo {
        id: profile
            .get("unionid")
            .and_then(Value::as_str)
            .filter(|id| !id.is_empty())
            .or_else(|| profile.get("openid").and_then(Value::as_str))
            .ok_or("Missing WeChat profile identifier")?
            .into(),
        name: profile
            .get("nickname")
            .cloned()
            .map(serde_json::from_value::<Option<String>>)
            .transpose()
            .map(|value| value.map(Into::into).unwrap_or_default())
            .map_err(|error| format!("Invalid WeChat nickname: {error}"))?,
        email: super::defaults::profile_email(&profile)?,
        image: profile
            .get("headimgurl")
            .cloned()
            .map(serde_json::from_value)
            .transpose()
            .map_err(|error| format!("Invalid WeChat image: {error}"))?,
        email_verified: Some(false).into(),
        additional_fields: Default::default(),
    })
}
