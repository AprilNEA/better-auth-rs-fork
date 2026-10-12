//! Application admission policy for user provisioning and provider authentication.

use super::endpoint_context::EndpointContext;
use async_trait::async_trait;
use better_auth_core::{AuthError, AuthResponse, AuthResult, AuthSchema, CreateUser};
use better_auth_core::{FieldMap, FieldValue, SchemaValue};
use serde::{Serialize, ser::SerializeMap};
use std::sync::Arc;

/// The operation that is subject to the admission policy.
#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum UserValidationAction {
    CreateUser,
    LinkAccount,
    SignIn,
}

/// Provider identity and the original, unmapped profile.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UserValidationProvider {
    #[serde(skip_serializing_if = "SchemaValue::is_json_omitted")]
    pub provider_id: SchemaValue<String>,
    /// Retain the original profile handle until the caller serializes the validation data.
    #[serde(
        skip_serializing_if = "better_auth_core::field_value::serde::optional_value::is_absent_or_json_omitted",
        with = "better_auth_core::field_value::serde::optional_value"
    )]
    pub profile: Option<FieldValue>,
}

/// Provenance of a user validation operation.
#[derive(Debug, Clone)]
pub struct UserValidationSource {
    pub action: UserValidationAction,
    pub method: String,
    pub oauth: Option<UserValidationProvider>,
    pub sso: Option<UserValidationProvider>,
    action_first: bool,
}

impl Serialize for UserValidationSource {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut map = serializer.serialize_map(None)?;
        if self.action_first {
            map.serialize_entry("action", &self.action)?;
        }
        map.serialize_entry("method", &self.method)?;
        if let Some(oauth) = &self.oauth {
            map.serialize_entry("oauth", oauth)?;
        }
        if let Some(sso) = &self.sso {
            map.serialize_entry("sso", sso)?;
        }
        if !self.action_first {
            map.serialize_entry("action", &self.action)?;
        }
        map.end()
    }
}
impl UserValidationSource {
    pub fn new(method: impl Into<String>, action: UserValidationAction) -> Self {
        Self {
            action,
            method: method.into(),
            oauth: None,
            sso: None,
            action_first: false,
        }
    }
    pub(crate) fn oauth(
        provider: &FieldValue,
        profile: Option<&FieldValue>,
        action: UserValidationAction,
    ) -> Self {
        Self {
            oauth: Some(UserValidationProvider {
                provider_id: SchemaValue::from_field(provider.clone()),
                profile: profile.cloned(),
            }),
            ..Self::new("oauth", action)
        }
    }

    pub(crate) fn explicit_oauth_link(provider: &FieldValue, profile: Option<&FieldValue>) -> Self {
        Self {
            action_first: true,
            ..Self::oauth(provider, profile, UserValidationAction::LinkAccount)
        }
    }
}

/// User input before database hooks and adapter field transforms.
#[derive(Debug, Clone, Serialize)]
pub struct UserValidationData {
    /// Public field names. Generated identifiers are absent during creation.
    #[serde(with = "better_auth_core::field_value::serde::map")]
    pub user: FieldMap,
    pub source: UserValidationSource,
}

/// A public rejection returned by the application's admission policy.
#[derive(Debug, Clone)]
pub struct UserValidationRejection {
    pub error: String,
    pub error_description: Option<String>,
}
impl UserValidationRejection {
    pub fn new(error: impl Into<String>) -> Self {
        Self {
            error: error.into(),
            error_description: None,
        }
    }
    pub fn with_description(mut self, description: impl Into<String>) -> Self {
        self.error_description = Some(description.into());
        self
    }
    pub(crate) fn message(&self) -> &str {
        self.error_description
            .as_deref()
            .filter(|value| !value.is_empty())
            .unwrap_or(&self.error)
    }
    pub(crate) fn into_auth_error(self) -> AuthError {
        match AuthResponse::json(
            403,
            &serde_json::json!({"code": self.error, "message": self.message()}),
        ) {
            Ok(response) => response.into(),
            Err(error) => error,
        }
    }
}

/// Equivalent to `user.validateUserInfo`. Returning `None` admits the operation.
///
/// Callback errors reject with `validation_failed` after logging. Logger errors propagate.
#[async_trait]
pub trait ValidateUserInfo<S: AuthSchema>: Send + Sync {
    async fn validate(
        &self,
        data: &UserValidationData,
        context: &EndpointContext<'_, S>,
    ) -> AuthResult<Option<UserValidationRejection>>;
}

pub(crate) async fn validate<S: AuthSchema>(
    data: UserValidationData,
    endpoint: &EndpointContext<'_, S>,
) -> AuthResult<Option<UserValidationRejection>> {
    let Some(callback) = endpoint
        .auth
        .extensions
        .get::<Arc<dyn ValidateUserInfo<S>>>()
    else {
        return Ok(None);
    };
    let invalid_source = if data.source.method.is_empty() {
        Some("User validation source is required")
    } else if data.source.method == "oauth"
        && data
            .source
            .oauth
            .as_ref()
            .is_none_or(|provider| !provider.provider_id.field_value().is_truthy())
    {
        Some("OAuth user validation source requires oauth.providerId")
    } else if matches!(data.source.method.as_str(), "sso-oidc" | "sso-saml")
        && data
            .source
            .sso
            .as_ref()
            .is_none_or(|provider| !provider.provider_id.field_value().is_truthy())
    {
        Some("SSO user validation source requires sso.providerId")
    } else {
        None
    };
    if let Some(message) = invalid_source {
        return Ok(Some(
            UserValidationRejection::new("validation_source_missing").with_description(message),
        ));
    }
    match callback.validate(&data, endpoint).await {
        Ok(Some(rejection)) if !rejection.error.is_empty() => Ok(Some(rejection)),
        Ok(_) => Ok(None),
        Err(error) => {
            // Upstream deliberately masks application exceptions at this fail-closed boundary.
            better_auth_core::observability::logger::current().error(
                "validateUserInfo callback threw",
                &[better_auth_core::observability::LogArgument::Error(&error)],
            )?;
            Ok(Some(
                UserValidationRejection::new("validation_failed")
                    .with_description("User validation failed"),
            ))
        }
    }
}

pub(crate) async fn validate_create<S: AuthSchema>(
    input: &FieldMap,
    source: UserValidationSource,
    endpoint: &EndpointContext<'_, S>,
) -> AuthResult<Option<UserValidationRejection>> {
    validate(
        UserValidationData {
            user: input.clone(),
            source,
        },
        endpoint,
    )
    .await
}

pub(crate) async fn create_user_optional<S: AuthSchema>(
    input: CreateUser,
    method: &str,
    endpoint: &EndpointContext<'_, S>,
) -> AuthResult<Option<better_auth_core::wire::UserView>> {
    let mut input = input.into_user_fields()?;
    if let Some(rejection) = validate_create(
        &input,
        UserValidationSource::new(method, UserValidationAction::CreateUser),
        endpoint,
    )
    .await?
    {
        return Err(rejection.into_auth_error());
    }
    super::helpers::apply_default_role(endpoint.auth, &mut input);
    match endpoint.transaction {
        Some(transaction) => transaction.create_user_fields_optional(input).await,
        None => {
            endpoint
                .auth
                .database
                .create_user_fields_optional(input)
                .await
        }
    }
}

#[cfg(test)]
#[path = "user_admission_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "user_admission_provider_tests.rs"]
mod provider_tests;
