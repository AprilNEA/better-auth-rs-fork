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
    pub redirect: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<bool>,
    #[serde(
        with = "better_auth_core::field_value::serde::value",
        skip_serializing_if = "better_auth_core::FieldValue::is_json_omitted"
    )]
    pub token: better_auth_core::FieldValue,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user: Option<serde_json::Value>,
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

#[derive(Debug, Serialize)]
pub(crate) struct AccountInfoUser {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(skip_serializing_if = "better_auth_core::SchemaValue::is_json_omitted")]
    pub name: better_auth_core::SchemaValue<Option<String>>,
    #[serde(skip_serializing_if = "better_auth_core::SchemaValue::is_json_omitted")]
    pub email: better_auth_core::SchemaValue<Option<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub image: Option<Option<String>>,
    #[serde(
        rename = "emailVerified",
        skip_serializing_if = "better_auth_core::SchemaValue::is_json_omitted"
    )]
    pub email_verified: better_auth_core::SchemaValue<Option<bool>>,
    #[serde(flatten)]
    #[serde(with = "better_auth_core::field_value::serde::map")]
    pub additional_fields: better_auth_core::FieldMap,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct AccountInfoAccount {
    #[serde(skip_serializing_if = "better_auth_core::SchemaValue::is_json_omitted")]
    pub id: better_auth_core::SchemaValue<String>,
    #[serde(skip_serializing_if = "better_auth_core::SchemaValue::is_json_omitted")]
    pub provider_id: better_auth_core::SchemaValue<String>,
    #[serde(skip_serializing_if = "better_auth_core::SchemaValue::is_json_omitted")]
    pub account_id: better_auth_core::SchemaValue<String>,
}

#[derive(Debug, Serialize)]
pub(crate) struct AccountInfoResponse {
    pub user: AccountInfoUser,
    pub data: serde_json::Value,
    pub account: AccountInfoAccount,
}

impl AccountInfoResponse {
    pub(super) fn into_field_value(self) -> better_auth_core::FieldValue {
        use better_auth_core::{FieldMap, FieldValue};
        let mut user = FieldMap::new();
        if let Some(id) = self.user.id {
            let _ = user.insert("id".into(), id.into());
        }
        user.extend([
            ("name".into(), self.user.name.into_field_value()),
            ("email".into(), self.user.email.into_field_value()),
        ]);
        if let Some(image) = self.user.image {
            let _ = user.insert(
                "image".into(),
                image.map(FieldValue::from).unwrap_or(FieldValue::Null),
            );
        }
        let _ = user.insert(
            "emailVerified".into(),
            self.user.email_verified.into_field_value(),
        );
        user.extend(self.user.additional_fields);
        let account = FieldMap::from([
            ("id".into(), self.account.id.into_field_value()),
            (
                "providerId".into(),
                self.account.provider_id.into_field_value(),
            ),
            (
                "accountId".into(),
                self.account.account_id.into_field_value(),
            ),
        ]);
        FieldMap::from([
            ("user".into(), user.into()),
            ("data".into(), self.data.into()),
            ("account".into(), account.into()),
        ])
        .into()
    }
}
