use super::*;
use better_auth_core::{
    AuthContext, AuthRequest, AuthResponse, Headers,
    observability::AfterEndpointHook,
    store::database_hooks::{
        DatabaseHookContext, DatabaseHookControl, DatabaseHookUpdate, DatabaseHooks,
        DatabaseUpdateResult,
    },
    wire::{AccountView, SessionView, UserView},
};

pub(super) struct Hooks {
    events: Events,
    branch: String,
    mode: String,
    callback: bool,
    failure: FieldValue,
}

fn cookies(request: &AuthRequest) -> AuthResult<Vec<String>> {
    Ok(
        Headers::from_field_value(&request.response_headers_value()?)?
            .get_all("set-cookie")
            .cloned()
            .collect(),
    )
}

impl Hooks {
    pub(super) fn new(events: Events, scenario: &Scenario) -> AuthResult<Self> {
        let failure = FieldValue::from_json(json!({
            "name": "APIError", "status": "CONFLICT", "statusCode": 409,
            "body": {"code": "ORDER_REJECTED", "message": "order rejection", "details": {"phase": scenario.mode.strip_prefix("raw-").unwrap_or(&scenario.mode)}},
            "headers": {"x-order-error": "1"},
        }))?;
        Ok(Self {
            events,
            branch: scenario.branch.clone(),
            mode: scenario.mode.clone(),
            callback: scenario.callback,
            failure,
        })
    }

    fn record<S: AuthSchema>(
        &self,
        model: &str,
        operation: &str,
        phase: &str,
        fields: FieldValue,
        context: &DatabaseHookContext<'_, S>,
    ) -> AuthResult<()> {
        let request = &context
            .request
            .as_ref()
            .ok_or_else(|| AuthError::internal("OAuth hook request missing"))?
            .request;
        self.events.push(json!({"kind": "hook-headers", "model": model, "operation": operation, "phase": phase, "cookies": cookies(request)?}))?;
        let keys: Vec<_> = fields.enumerable_fields()?.keys().cloned().collect();
        self.events.push(json!({"kind": "hook", "model": model, "operation": operation, "phase": phase, "keys": keys, "data": values::observe(&fields)?}))?;
        if model == "account" && self.mode == format!("raw-{phase}") {
            return Err(AuthError::from_thrown(self.failure.clone()));
        }
        Ok(())
    }
}

#[better_auth_core::database_hooks()]
impl<S: AuthSchema> DatabaseHooks<S> for Hooks {
    async fn before_create_user(
        &self,
        data: &mut FieldMap,
        context: &DatabaseHookContext<'_, S>,
    ) -> AuthResult<DatabaseHookUpdate<FieldMap>> {
        self.record("user", "create", "before", data.clone().into(), context)?;
        Ok(DatabaseHookUpdate::Continue)
    }
    async fn after_create_user(
        &self,
        data: Option<&UserView>,
        context: &DatabaseHookContext<'_, S>,
    ) -> AuthResult<()> {
        self.record(
            "user",
            "create",
            "after",
            data.cloned()
                .map(FieldMap::from)
                .map_or(FieldValue::Null, Into::into),
            context,
        )
    }
    async fn before_create_account(
        &self,
        data: &mut CreateAccount,
        context: &DatabaseHookContext<'_, S>,
    ) -> AuthResult<DatabaseHookControl> {
        assert_ne!(self.branch, "existing");
        self.record(
            "account",
            "create",
            "before",
            data.fields()?.into(),
            context,
        )?;
        Ok(DatabaseHookControl::Continue)
    }
    async fn after_create_account(
        &self,
        data: Option<&AccountView>,
        context: &DatabaseHookContext<'_, S>,
    ) -> AuthResult<()> {
        self.record(
            "account",
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
        assert_eq!(self.branch, "existing");
        self.record("account", "update", "before", data.clone().into(), context)?;
        Ok(if self.mode == "cancel-before" {
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
            return Err(AuthError::internal("OAuth update must target one Account"));
        };
        self.record(
            "account",
            "update",
            "after",
            data.map(AccountView::internal_fields)
                .transpose()?
                .map_or(FieldValue::Null, Into::into),
            context,
        )
    }
    async fn before_create_session(
        &self,
        data: &mut FieldMap,
        context: &DatabaseHookContext<'_, S>,
    ) -> AuthResult<DatabaseHookUpdate<FieldMap>> {
        self.record("session", "create", "before", data.clone().into(), context)?;
        Ok(DatabaseHookUpdate::Continue)
    }
    async fn after_create_session(
        &self,
        data: Option<&SessionView>,
        context: &DatabaseHookContext<'_, S>,
    ) -> AuthResult<()> {
        self.record(
            "session",
            "create",
            "after",
            data.cloned()
                .map(FieldMap::from)
                .map_or(FieldValue::Null, Into::into),
            context,
        )
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
        if self.callback && request.path() != "/callback/google" {
            return Ok(());
        }
        let cookies: Vec<_> = response.headers.get_all("set-cookie").collect();
        self.events.push(json!({"kind": "endpoint-after", "rawErrorIdentity": response.body.field_value()?.strict_equals(&self.failure), "cookies": cookies}))
    }
}
