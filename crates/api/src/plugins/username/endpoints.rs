use better_auth_core::{
    AuthContext, AuthError, AuthRequest, AuthResponse, AuthResult, AuthSchema, FieldValue,
    RequestMeta,
};
use serde_json::json;

use super::{UsernamePlugin, UsernameValidationOrder, request};
use crate::plugins::email_password::{
    EmailPasswordConfig, SignInUsernameFailure, sign_in_username_core,
};

impl UsernamePlugin {
    pub(crate) async fn available<S: AuthSchema>(
        &self,
        request: &AuthRequest,
        context: &AuthContext<S>,
    ) -> AuthResult<AuthResponse> {
        let username = request::availability(request)?;
        if username.is_empty() {
            return Err(AuthError::from_code(
                "UNPROCESSABLE_ENTITY",
                "INVALID_USERNAME",
                "Username is invalid",
            ));
        }
        let username = FieldValue::from(username);
        if let Some((code, message)) = self.config.validate_raw(&username).await? {
            return Err(AuthError::from_code("UNPROCESSABLE_ENTITY", code, message));
        }
        let found = context
            .database
            .get_user_by_field_value("username", &self.config.normalize(&username)?)
            .await?;
        AuthResponse::json(None, &json!({"available": found.is_none()}))
    }

    pub(super) async fn sign_in<S: AuthSchema>(
        &self,
        request: &AuthRequest,
        context: &AuthContext<S>,
    ) -> AuthResult<AuthResponse> {
        self.sign_in_with_verification(request, context, None).await
    }

    pub(crate) async fn sign_in_with_verification<S: AuthSchema>(
        &self,
        request: &AuthRequest,
        context: &AuthContext<S>,
        verification: Option<&crate::plugins::email_verification::EmailVerificationPlugin>,
    ) -> AuthResult<AuthResponse> {
        let body = request::sign_in(request)?;
        if body.username.is_empty() || body.password.is_empty() {
            return Err(AuthError::from_code(
                "UNAUTHORIZED",
                "INVALID_USERNAME_OR_PASSWORD",
                "Invalid username or password",
            ));
        }
        let username = if self.config.username_validation_order
            == Some(UsernameValidationOrder::PreNormalization)
        {
            self.config.normalize(&body.username.clone().into())?
        } else {
            body.username.clone().into()
        };
        if let Some((code, message)) = self.config.validate_raw(&username).await? {
            return Err(AuthError::from_code("UNPROCESSABLE_ENTITY", code, message));
        }
        let username = self.config.normalize(&username)?;
        let fallback = EmailPasswordConfig::default();
        let password = context
            .extensions
            .get::<EmailPasswordConfig>()
            .unwrap_or(&fallback);
        let meta =
            RequestMeta::from_request_with_config(request, &context.config.advanced.ip_address);
        let result = sign_in_username_core(
            request,
            &body,
            &username,
            password,
            verification,
            &meta,
            context,
        )
        .await;
        match result {
            Ok(result) => {
                let mut response = AuthResponse::native(None, result.response.into_field_value()?);
                if let Some(callback) = body.callback_url.filter(|value| !value.is_empty()) {
                    let _ = response.headers.insert("Location", callback);
                }
                Ok(response)
            }
            Err(SignInUsernameFailure::InvalidUsernameOrPassword) => Err(AuthError::from_code(
                "UNAUTHORIZED",
                "INVALID_USERNAME_OR_PASSWORD",
                "Invalid username or password",
            )),
            Err(SignInUsernameFailure::EmailNotVerified) => Err(AuthError::from_code(
                "FORBIDDEN",
                "EMAIL_NOT_VERIFIED",
                "Email not verified",
            )),
            Err(SignInUsernameFailure::Auth(error)) => Err(error),
        }
    }
}
