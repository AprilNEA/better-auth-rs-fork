use super::*;
use better_auth_core::{
    AuthRecordFields, CreateAccount,
    store::{
        StatelessSchema,
        database_hooks::{
            DatabaseHookContext, DatabaseHookControl, DatabaseHookUpdate, DatabaseHooks,
        },
    },
    wire::{AccountView, SessionView, UserView},
};

pub(super) struct Hooks(pub Arc<State>);

#[async_trait::async_trait]
impl better_auth_core::AuthPlugin<StatelessSchema> for Hooks {
    fn name(&self) -> &'static str {
        "native-profile-contract-hooks"
    }
    fn routes(&self) -> Vec<better_auth_core::AuthRoute> {
        Vec::new()
    }
    async fn on_init(
        &self,
        context: &mut better_auth_core::AuthInitContext<StatelessSchema>,
    ) -> AuthResult<()> {
        context.register_database_hook(Arc::new(Self(self.0.clone())));
        Ok(())
    }
    async fn on_request(
        &self,
        _: &better_auth_core::AuthRequest,
        _: &better_auth_core::AuthContext<StatelessSchema>,
    ) -> AuthResult<Option<better_auth_core::AuthResponse>> {
        Ok(None)
    }
}

impl Hooks {
    fn event(&self, model: &str, phase: &str, data: FieldMap) -> AuthResult<()> {
        self.0.generated_record_dates(&data, model == "session")?;
        if model == "session" && phase == "before" {
            let token = data.get("token").unwrap().as_str().unwrap();
            self.0.remember(token, "session-token");
            self.0.tracking.lock().unwrap().session_token = Some(token.into());
        }
        self.0
            .log
            .event(json!({"kind": "hook", "model": model, "phaseInHook": phase,
            "data": observe::native(&data.into())?}));
        Ok(())
    }
}

#[better_auth_core::database_hooks()]
impl DatabaseHooks<StatelessSchema> for Hooks {
    async fn before_create_user(
        &self,
        data: &mut FieldMap,
        _: &DatabaseHookContext<'_, StatelessSchema>,
    ) -> AuthResult<DatabaseHookUpdate<FieldMap>> {
        self.event("user", "before", data.clone())?;
        Ok(DatabaseHookUpdate::Continue)
    }
    async fn after_create_user(
        &self,
        data: Option<&UserView>,
        _: &DatabaseHookContext<'_, StatelessSchema>,
    ) -> AuthResult<()> {
        self.event("user", "after", data.unwrap().field_values()?)
    }
    async fn before_create_account(
        &self,
        data: &mut CreateAccount,
        _: &DatabaseHookContext<'_, StatelessSchema>,
    ) -> AuthResult<DatabaseHookControl> {
        self.event("account", "before", data.fields()?)?;
        Ok(DatabaseHookControl::Continue)
    }
    async fn after_create_account(
        &self,
        data: Option<&AccountView>,
        _: &DatabaseHookContext<'_, StatelessSchema>,
    ) -> AuthResult<()> {
        self.event("account", "after", data.unwrap().field_values()?)
    }
    async fn before_create_session(
        &self,
        data: &mut FieldMap,
        _: &DatabaseHookContext<'_, StatelessSchema>,
    ) -> AuthResult<DatabaseHookUpdate<FieldMap>> {
        self.event("session", "before", data.clone())?;
        Ok(DatabaseHookUpdate::Continue)
    }
    async fn after_create_session(
        &self,
        data: Option<&SessionView>,
        _: &DatabaseHookContext<'_, StatelessSchema>,
    ) -> AuthResult<()> {
        self.event("session", "after", FieldMap::from(data.unwrap().clone()))
    }
}
