use indexmap::IndexMap;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Deserialize)]
pub(crate) struct SocialSignInRequest {
    pub provider: String,
    #[serde(rename = "callbackURL")]
    pub callback_url: Option<String>,
    #[serde(rename = "newUserCallbackURL")]
    pub new_user_callback_url: Option<String>,
    #[serde(rename = "errorCallbackURL")]
    pub error_callback_url: Option<String>,
    #[serde(rename = "disableRedirect")]
    pub disable_redirect: Option<bool>,
    #[serde(rename = "idToken")]
    pub id_token: Option<OAuthIdTokenRequest>,
    #[serde(rename = "requestSignUp")]
    pub request_sign_up: Option<bool>,
    #[serde(rename = "loginHint")]
    pub login_hint: Option<String>,
    #[serde(rename = "additionalData")]
    pub additional_data: Option<serde_json::Map<String, serde_json::Value>>,
    pub scopes: Option<Vec<String>>,
    #[serde(rename = "additionalParams")]
    pub additional_params: Option<IndexMap<String, String>>,
}

#[derive(Debug, Clone, Deserialize)]
pub(crate) struct LinkSocialRequest {
    pub provider: String,
    #[serde(rename = "callbackURL")]
    pub callback_url: Option<String>,
    #[serde(rename = "errorCallbackURL")]
    pub error_callback_url: Option<String>,
    #[serde(rename = "disableRedirect")]
    pub disable_redirect: Option<bool>,
    #[serde(rename = "idToken")]
    pub id_token: Option<OAuthIdTokenRequest>,
    #[serde(rename = "requestSignUp")]
    pub request_sign_up: Option<bool>,
    #[serde(rename = "loginHint")]
    pub login_hint: Option<String>,
    #[serde(rename = "additionalData")]
    pub additional_data: Option<serde_json::Map<String, serde_json::Value>>,
    pub scopes: Option<Vec<String>>,
    #[serde(rename = "additionalParams")]
    pub additional_params: Option<IndexMap<String, String>>,
}

#[derive(Debug, Clone, Deserialize)]
pub(crate) struct OAuthIdTokenRequest {
    pub token: String,
    pub nonce: Option<String>,
    #[serde(rename = "accessToken")]
    pub access_token: Option<String>,
    #[serde(rename = "refreshToken")]
    pub refresh_token: Option<String>,
    pub user: Option<super::providers::OAuthCallbackUserPayload>,
}

#[derive(Debug, Serialize)]
pub(crate) struct SocialSignInResponse {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<bool>,
    pub redirect: bool,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct AccessTokenResponse {
    #[serde(skip_serializing_if = "better_auth_core::SchemaValue::is_json_omitted")]
    pub access_token: better_auth_core::SchemaValue<Option<String>>,
    #[serde(
        skip_serializing_if = "better_auth_core::SchemaValue::is_json_omitted",
        serialize_with = "better_auth_core::schema_value::serialize_optional_date"
    )]
    pub access_token_expires_at: better_auth_core::SchemaValue<Option<better_auth_core::FieldDate>>,
    pub scopes: better_auth_core::SchemaValue<Vec<String>>,
    #[serde(skip_serializing_if = "better_auth_core::SchemaValue::is_json_omitted")]
    pub id_token: better_auth_core::SchemaValue<Option<String>>,
}

impl AccessTokenResponse {
    pub(super) fn into_field_value(self) -> better_auth_core::FieldValue {
        use better_auth_core::FieldMap;
        FieldMap::from([
            ("accessToken".into(), self.access_token.into_field_value()),
            (
                "accessTokenExpiresAt".into(),
                self.access_token_expires_at.into_field_value(),
            ),
            ("scopes".into(), self.scopes.into_field_value()),
            ("idToken".into(), self.id_token.into_field_value()),
        ])
        .into()
    }
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct RefreshTokenResponse {
    #[serde(skip_serializing_if = "better_auth_core::SchemaValue::is_json_omitted")]
    pub access_token: better_auth_core::SchemaValue<Option<String>>,
    #[serde(skip_serializing_if = "better_auth_core::SchemaValue::is_json_omitted")]
    pub refresh_token: better_auth_core::SchemaValue<Option<String>>,
    #[serde(
        skip_serializing_if = "better_auth_core::SchemaValue::is_json_omitted",
        serialize_with = "better_auth_core::schema_value::serialize_optional_date"
    )]
    pub access_token_expires_at: better_auth_core::SchemaValue<Option<better_auth_core::FieldDate>>,
    #[serde(
        skip_serializing_if = "better_auth_core::SchemaValue::is_json_omitted",
        serialize_with = "better_auth_core::schema_value::serialize_optional_date"
    )]
    pub refresh_token_expires_at:
        better_auth_core::SchemaValue<Option<better_auth_core::FieldDate>>,
    #[serde(skip_serializing_if = "better_auth_core::SchemaValue::is_json_omitted")]
    pub scope: better_auth_core::SchemaValue<Option<String>>,
    #[serde(skip_serializing_if = "better_auth_core::SchemaValue::is_json_omitted")]
    pub id_token: better_auth_core::SchemaValue<Option<String>>,
    #[serde(skip_serializing_if = "better_auth_core::SchemaValue::is_json_omitted")]
    pub provider_id: better_auth_core::SchemaValue<String>,
    #[serde(skip_serializing_if = "better_auth_core::SchemaValue::is_json_omitted")]
    pub account_id: better_auth_core::SchemaValue<String>,
}

impl RefreshTokenResponse {
    pub(super) fn into_field_value(self) -> better_auth_core::FieldValue {
        use better_auth_core::FieldMap;
        FieldMap::from([
            ("accessToken".into(), self.access_token.into_field_value()),
            ("refreshToken".into(), self.refresh_token.into_field_value()),
            (
                "accessTokenExpiresAt".into(),
                self.access_token_expires_at.into_field_value(),
            ),
            (
                "refreshTokenExpiresAt".into(),
                self.refresh_token_expires_at.into_field_value(),
            ),
            ("scope".into(), self.scope.into_field_value()),
            ("idToken".into(), self.id_token.into_field_value()),
            ("providerId".into(), self.provider_id.into_field_value()),
            ("accountId".into(), self.account_id.into_field_value()),
        ])
        .into()
    }
}
