use super::*;
use better_auth::plugins::{
    endpoint_context::EndpointContext,
    user_admission::{UserValidationData, UserValidationRejection, ValidateUserInfo},
};
use better_auth_core::{
    AuthContext, AuthRequest, AuthResponse, Headers,
    api_error::{ApiErrorHandler, ApiErrorTask},
    observability::AfterEndpointHook,
    store::database_hooks::{
        DatabaseHookContext, DatabaseHookControl, DatabaseHookUpdate, DatabaseHooks,
        DatabaseUpdateResult,
    },
    wire::AccountView,
};

pub(super) struct Hooks {
    pub(super) failure: FieldValue,
    callbacks: callbacks::Callbacks,
    mode: String,
}

pub(super) fn header_state(value: &FieldValue) -> AuthResult<Value> {
    if value.is_undefined() {
        return values::observe(value);
    }
    let headers = Headers::from_field_value(value)?;
    let mut entries: Vec<_> = headers
        .iter()
        .map(|(name, value)| [name.to_owned(), value.clone()])
        .collect();
    entries.sort_by(|left, right| {
        (left[0] == "set-cookie")
            .cmp(&(right[0] == "set-cookie"))
            .then_with(|| left[0].cmp(&right[0]))
    });
    let cookies: Vec<_> = headers.get_all("set-cookie").cloned().collect();
    Ok(json!({"entries": entries, "cookies": cookies}))
}

impl Hooks {
    pub(super) fn new(events: Events, scenario: &Scenario) -> AuthResult<Self> {
        let failure = if scenario.mode == "after-error" {
            json!({"name": "Error", "message": "link runtime failure"})
        } else {
            json!({
                "name": "APIError", "message": "link rejection", "status": "CONFLICT", "statusCode": 409,
                "body": {"code": if scenario.mode == "admission-uncoded" { "" } else { "LINK_REJECTED" },
                    "message": "link rejection", "details": {"mode": scenario.mode}},
                "headers": {"x-link-error": "1"},
            })
        };
        Ok(Self {
            failure: FieldValue::from_json(failure)?,
            callbacks: callbacks::Callbacks {
                events,
                accounts_one: false,
                callback: scenario.callback,
                branch: scenario.branch.clone(),
            },
            mode: scenario.mode.clone(),
        })
    }

    pub(super) fn observe_error(&self, error: &AuthError) -> AuthResult<Value> {
        let raw = error
            .raw_value()
            .ok_or_else(|| AuthError::internal("Link error lost its native value"))?;
        let body = raw.model_property("body")?;
        let headers = raw.model_property("headers")?;
        Ok(json!({
            "sameObject": raw.strict_equals(&self.failure),
            "sameBody": body.strict_equals(&self.failure.model_property("body")?),
            "sameHeaders": headers.strict_equals(&self.failure.model_property("headers")?),
            "name": values::observe(&raw.model_property("name")?)?,
            "message": values::observe(&raw.model_property("message")?)?,
            "status": values::observe(&raw.model_property("status")?)?,
            "statusCode": values::observe(&raw.model_property("statusCode")?)?,
            "body": values::observe(&body)?, "headers": header_state(&headers)?,
            "capturedHeaders": header_state(&error.captured_headers_value().unwrap_or(FieldValue::Undefined))?,
        }))
    }

    fn record<S: AuthSchema>(
        &self,
        operation: &str,
        phase: &str,
        data: FieldValue,
        context: &DatabaseHookContext<'_, S>,
    ) -> AuthResult<()> {
        let request = &context
            .request
            .as_ref()
            .ok_or_else(|| AuthError::internal("Link database hook request missing"))?
            .request;
        let headers = Headers::from_field_value(&request.response_headers_value()?)?;
        let cookies: Vec<_> = headers.get_all("set-cookie").collect();
        self.callbacks.events.push(json!({"kind": "hook-headers", "model": "account", "operation": operation, "phase": phase, "cookies": cookies}))?;
        let keys: Vec<_> = if data.is_null() {
            Vec::new()
        } else {
            data.enumerable_fields()?.keys().cloned().collect()
        };
        self.callbacks.events.push(json!({"kind": "hook", "model": "account", "operation": operation, "phase": phase, "keys": keys, "data": values::observe(&data)?}))?;
        if (self.mode == "before-api" && phase == "before")
            || (self.mode == "after-error" && phase == "after")
        {
            return Err(AuthError::from_thrown(self.failure.clone()));
        }
        Ok(())
    }
}

#[better_auth_core::database_hooks()]
impl<S: AuthSchema> DatabaseHooks<S> for Hooks {
    async fn before_create_account(
        &self,
        data: &mut CreateAccount,
        context: &DatabaseHookContext<'_, S>,
    ) -> AuthResult<DatabaseHookControl> {
        self.record("create", "before", data.fields()?.into(), context)?;
        Ok(if self.mode == "cancel" {
            DatabaseHookControl::Cancel
        } else {
            DatabaseHookControl::Continue
        })
    }

    async fn after_create_account(
        &self,
        data: Option<&AccountView>,
        context: &DatabaseHookContext<'_, S>,
    ) -> AuthResult<()> {
        self.record(
            "create",
            "after",
            data.map(AccountView::internal_fields)
                .transpose()?
                .map_or(FieldValue::Null, Into::into),
            context,
        )
    }

    async fn before_update_account(
        &self,
        data: &mut FieldMap,
        context: &DatabaseHookContext<'_, S>,
    ) -> AuthResult<DatabaseHookUpdate<FieldMap>> {
        self.record("update", "before", data.clone().into(), context)?;
        Ok(if self.mode == "cancel" {
            DatabaseHookUpdate::Cancel
        } else {
            DatabaseHookUpdate::Continue
        })
    }

    async fn after_update_account(
        &self,
        data: DatabaseUpdateResult<&AccountView>,
        context: &DatabaseHookContext<'_, S>,
    ) -> AuthResult<()> {
        let DatabaseUpdateResult::One(data) = data else {
            return Err(AuthError::internal("Link update must target one Account"));
        };
        self.record(
            "update",
            "after",
            data.map(AccountView::internal_fields)
                .transpose()?
                .map_or(FieldValue::Null, Into::into),
            context,
        )
    }
}

#[async_trait::async_trait]
impl<S: AuthSchema> ValidateUserInfo<S> for Hooks {
    async fn validate(
        &self,
        data: &UserValidationData,
        context: &EndpointContext<'_, S>,
    ) -> AuthResult<Option<UserValidationRejection>> {
        let result = self.callbacks.validate(data, context).await?;
        if self.mode.starts_with("admission-") {
            return Err(AuthError::from_thrown(self.failure.clone()));
        }
        Ok(result)
    }
}

#[async_trait::async_trait]
impl<S: AuthSchema> AfterEndpointHook<S> for Hooks {
    async fn after(
        &self,
        request: &AuthRequest,
        response: &mut AuthResponse,
        _: &AuthContext<S>,
    ) -> AuthResult<()> {
        if self.callbacks.callback && request.path() != "/callback/google" {
            return Ok(());
        }
        let cookies: Vec<_> = response.headers.get_all("set-cookie").collect();
        self.callbacks.events.push(json!({"kind": "endpoint-after", "rawErrorIdentity": response.body.field_value()?.strict_equals(&self.failure), "cookies": cookies}))
    }
}

impl<S: AuthSchema> ApiErrorHandler<S> for Hooks {
    fn on_error(&self, error: &AuthError, _: &AuthContext<S>) -> AuthResult<Option<ApiErrorTask>> {
        self.callbacks
            .events
            .push(json!({"kind": "api-error", "error": self.observe_error(error)?}))?;
        Ok(None)
    }
}
