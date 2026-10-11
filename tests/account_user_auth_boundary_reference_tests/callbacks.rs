use super::*;
use better_auth::plugins::{
    endpoint_context::EndpointContext,
    oauth::{
        OAuthIdTokenVerifier, OAuthUserInfo, OAuthUserInfoHandler, OAuthUserInfoRequest,
        OAuthUserInfoResponse,
    },
    user_admission::{UserValidationData, UserValidationRejection, ValidateUserInfo},
};
use better_auth_core::{
    AuthContext, HttpMethod, NativeRequest,
    api_error::{ApiErrorHandler, ApiErrorTask},
    utils::password::PasswordHasher,
};

pub(super) struct Callbacks {
    pub(super) events: Events,
    pub(super) accounts_one: bool,
    pub(super) callback: bool,
    pub(super) branch: String,
}

#[async_trait::async_trait]
impl OAuthIdTokenVerifier for Callbacks {
    async fn verify_id_token(
        &self,
        token: &str,
        nonce: Option<&str>,
        _: Option<NativeRequest<'_>>,
    ) -> Result<bool, String> {
        self.events
            .push(json!({"kind": "provider.verify", "token": token, "nonce": nonce}))
            .map_err(|error| error.to_string())?;
        Ok(token == ID_TOKEN && nonce == Some(NONCE))
    }
}

#[async_trait::async_trait]
impl OAuthUserInfoHandler for Callbacks {
    async fn get_user_info(
        &self,
        tokens: OAuthUserInfoRequest,
    ) -> AuthResult<Option<OAuthUserInfoResponse>> {
        assert!(tokens.user.field_value().is_undefined());
        let token_fields = tokens.fields();
        assert_eq!(
            token_fields
                .get("raw")
                .is_some_and(|value| !value.is_undefined()),
            self.callback
        );
        self.events.push(
            json!({"kind": "provider.userInfo", "tokens": values::observe(&token_fields.into())?}),
        )?;
        let id = if self.branch == "new" {
            "external-new"
        } else if self.branch == "implicit" {
            "external-implicit"
        } else if self.accounts_one {
            "external-unlinked"
        } else {
            "external-owner"
        };
        let email = if self.branch == "new" {
            "fresh@account-user-auth-boundary.test"
        } else {
            "a@account-user-auth-boundary.test"
        };
        Ok(Some(OAuthUserInfoResponse {
            user: OAuthUserInfo {
                id: id.into(),
                name: Some("Provider User".into()).into(),
                email: Some(email.into()).into(),
                email_verified: Some(true).into(),
                image: Some(Some("provider-image".into())),
                additional_fields: Default::default(),
            },
            data: json!({"sub": id, "name": "Provider User", "email": email, "email_verified": true, "picture": "provider-image"}),
        }))
    }
}

#[async_trait::async_trait]
impl<S: AuthSchema> ValidateUserInfo<S> for Callbacks {
    async fn validate(
        &self,
        data: &UserValidationData,
        context: &EndpointContext<'_, S>,
    ) -> AuthResult<Option<UserValidationRejection>> {
        let request = context
            .request
            .ok_or_else(|| AuthError::internal("HTTP admission request missing"))?;
        let method = if self.callback {
            HttpMethod::Get
        } else {
            HttpMethod::Post
        };
        assert_eq!(request.method, method);
        let mut headers: Vec<_> = request
            .headers
            .iter()
            .map(|(name, value)| [name.clone(), value.clone()])
            .collect();
        headers.sort();
        self.events.push(json!({
            "kind": "admission",
            "data": {"user": values::observe(&data.user.clone().into())?, "source": data.source},
            "request": {"url": request.url().map(url::Url::as_str), "method": if self.callback { "GET" } else { "POST" }, "headers": headers},
        }))?;
        Ok(None)
    }
}

#[async_trait::async_trait]
impl PasswordHasher for Callbacks {
    async fn hash(&self, value: &str) -> AuthResult<String> {
        self.events
            .push(json!({"kind": "password.hash", "value": value}))?;
        Ok(PASSWORD_HASH.into())
    }
    async fn verify(&self, hash: &str, password: &str) -> AuthResult<bool> {
        self.events.push(
            json!({"kind": "password.verify", "value": {"hash": hash, "password": password}}),
        )?;
        Ok(hash == PASSWORD_HASH && password == PASSWORD)
    }
}

impl<S: AuthSchema> ApiErrorHandler<S> for Callbacks {
    fn on_error(&self, error: &AuthError, _: &AuthContext<S>) -> AuthResult<Option<ApiErrorTask>> {
        if !self.branch.is_empty() {
            let AuthError::Internal(message) = error else {
                return Err(AuthError::internal(format!(
                    "Unexpected order contract router error: {error:?}"
                )));
            };
            self.events.push(
                json!({"kind": "api-error", "error": {"name": "Error", "message": message}}),
            )?;
            return Ok(None);
        }
        let variant = match error {
            AuthError::Internal(_) => "internal",
            AuthError::Database(_) => "database",
            _ => "unexpected",
        };
        self.events.push(json!({"kind": "api-error", "native": {
            "variant": variant, "message": error.to_string(), "debug": format!("{error:?}"), "isApiError": error.is_api_error()?,
        }}))?;
        Ok(None)
    }
}
