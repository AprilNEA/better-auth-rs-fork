use super::BodyTrace;
use better_auth::plugins::oauth::{
    OAuthIdTokenVerifier, OAuthPlugin, OAuthProvider, OAuthUserInfo, OAuthUserInfoHandler,
    OAuthUserInfoRequest, OAuthUserInfoResponse,
};
use better_auth_core::{AuthResult, FieldValue};
use serde_json::json;
use std::sync::Arc;

pub(super) fn plugin(profile: &str, trace: BodyTrace) -> OAuthPlugin {
    let plugin = OAuthPlugin::new();
    if !profile.starts_with("request-oauth-") {
        return plugin;
    }
    let trace = Arc::new(trace);
    let mut provider = OAuthProvider::google("fixture-client", "fixture-secret");
    provider.verify_id_token = Some(trace.clone());
    provider.get_user_info = Some(trace);
    plugin.add_provider("google", provider)
}

#[async_trait::async_trait]
impl OAuthIdTokenVerifier for BodyTrace {
    async fn verify_id_token(
        &self,
        token: &str,
        _: Option<&str>,
        _: Option<better_auth_core::NativeRequest<'_>>,
    ) -> Result<bool, String> {
        self.current("oauth.verify", None);
        Ok(token != "rejected-token")
    }
}

#[async_trait::async_trait]
impl OAuthUserInfoHandler for BodyTrace {
    async fn get_user_info(
        &self,
        request: OAuthUserInfoRequest,
    ) -> AuthResult<Option<OAuthUserInfoResponse>> {
        self.current("oauth.userinfo", None);
        let expires_at = request.access_token_expires_at.json()?;
        let scopes = request
            .scopes
            .json()?
            .filter(|value| !value.is_null())
            .unwrap_or_else(|| json!([]));
        let user = request.user.field_value();
        let property = |value: &FieldValue, name: &str| {
            if value.is_null() || value.is_undefined() {
                Ok(FieldValue::Undefined)
            } else {
                value.model_property(name)
            }
        };
        let first_name = property(&property(&user, "name")?, "firstName")?;
        let last_name = property(&property(&user, "name")?, "lastName")?;
        let email = property(&user, "email")?;
        self.1.lock().unwrap().push(json!({
            "kind":"oauth-userinfo", "accessToken":request.access_token,
            "refreshToken":request.refresh_token, "expiresAt":expires_at,
            "scopes":scopes, "idToken":request.id_token,
            "userPresent":!user.is_undefined(),
            "firstName":first_name.json()?,
            "lastName":last_name.json()?,
            "email":email.json()?,
        }));
        let email = request
            .access_token
            .field_value()
            .as_str()
            .ok_or_else(|| better_auth_core::AuthError::internal("Missing fixture access token"))?
            .to_owned();
        Ok(Some(OAuthUserInfoResponse {
            data: json!({"sub":email}),
            user: OAuthUserInfo {
                id: email.clone(),
                email: Some(email).into(),
                name: Some("OAuth schema".into()).into(),
                email_verified: Some(true).into(),
                image: None,
                additional_fields: Default::default(),
            },
        }))
    }
}
