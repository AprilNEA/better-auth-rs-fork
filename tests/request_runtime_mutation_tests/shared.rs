use super::*;
use better_auth_core::{
    AuthInitContext, CreateVerification, FieldDate,
    plugin_runtime::PluginRuntime,
    store::database_hooks::{DatabaseHookContext, DatabaseHookControl, DatabaseHooks},
    wire::VerificationView,
};
use std::sync::OnceLock;

#[derive(Clone, Default)]
struct Shared {
    events: Arc<Mutex<Vec<&'static str>>>,
    retained: Arc<Mutex<Option<Arc<AuthContext<S>>>>>,
    runtime: Arc<OnceLock<PluginRuntime<S>>>,
}

impl Shared {
    fn observe(
        &self,
        phase: &'static str,
        context: &AuthContext<S>,
        expected: &str,
    ) -> AuthResult<()> {
        let active = active(context);
        assert!(Arc::ptr_eq(
            lock(&self.retained)?
                .as_ref()
                .expect("Before hook retains context"),
            &active
        ));
        assert_eq!(context.base_url(), expected);
        lock(&self.events)?.push(phase);
        Ok(())
    }
}

#[async_trait]
impl BeforeEndpointHook<S> for Shared {
    async fn before(
        &self,
        _: &AuthRequest,
        context: &AuthContext<S>,
    ) -> AuthResult<Option<BeforeRequestAction>> {
        *lock(&self.retained)? = Some(active(context));
        self.observe("before", context, INITIAL_URL)?;
        context.set_base_url(changed("before"));
        Ok(None)
    }
}

#[async_trait]
impl AfterEndpointHook<S> for Shared {
    async fn after(
        &self,
        _: &AuthRequest,
        _: &mut AuthResponse,
        context: &AuthContext<S>,
    ) -> AuthResult<()> {
        self.observe("after", context, &changed("database-after"))?;
        context.set_base_url(changed("after"));
        Ok(())
    }
}

#[better_auth::database_hooks()]
impl DatabaseHooks<S> for Shared {
    async fn before_create_verification(
        &self,
        _: &mut CreateVerification,
        _: &DatabaseHookContext<'_, S>,
    ) -> AuthResult<DatabaseHookControl> {
        let context = self
            .runtime
            .get()
            .expect("Plugin runtime is bound")
            .context()?;
        self.observe("database-before", &context, &changed("handler"))?;
        context.set_base_url(changed("database-before"));
        Ok(DatabaseHookControl::Continue)
    }

    async fn after_create_verification(
        &self,
        _: Option<&VerificationView>,
        _: &DatabaseHookContext<'_, S>,
    ) -> AuthResult<()> {
        let context = self
            .runtime
            .get()
            .expect("Plugin runtime is bound")
            .context()?;
        self.observe("database-after", &context, &changed("database-before"))?;
        context.set_base_url(changed("database-after"));
        Ok(())
    }
}

fn row() -> CreateVerification {
    CreateVerification {
        id: "runtime-verification".into(),
        identifier: "runtime".into(),
        value: "stored".into(),
        created_at: FieldDate::from_milliseconds(1_893_456_000_000.0).into(),
        updated_at: FieldDate::from_milliseconds(1_893_456_000_001.0).into(),
        expires_at: FieldDate::from_milliseconds(1_893_456_060_000.0).into(),
        ..Default::default()
    }
}

#[async_trait]
impl AuthPlugin<S> for Shared {
    fn name(&self) -> &'static str {
        "runtime-shared"
    }
    fn routes(&self) -> Vec<AuthRoute> {
        vec![AuthRoute::new(
            HttpMethod::Get,
            "/runtime-shared",
            "runtimeShared",
        )]
    }
    async fn on_init(&self, context: &mut AuthInitContext<S>) -> AuthResult<()> {
        assert!(self.runtime.set(context.runtime()).is_ok());
        context.register_database_hook(Arc::new(self.clone()));
        Ok(())
    }
    async fn before_request(
        &self,
        _: &AuthRequest,
        context: &AuthContext<S>,
    ) -> AuthResult<Option<BeforeRequestAction>> {
        self.observe("plugin-before", context, &changed("before"))?;
        context.set_base_url(changed("plugin-before"));
        Ok(None)
    }
    async fn on_request(
        &self,
        _: &AuthRequest,
        context: &AuthContext<S>,
    ) -> AuthResult<Option<AuthResponse>> {
        self.observe("handler", context, &changed("plugin-before"))?;
        context.set_base_url(changed("handler"));
        let stored = context.database.create_verification(row()).await?;
        assert_eq!(
            serde_json::to_value(stored)?,
            FieldValue::from(row().fields()?)
                .json()?
                .expect("Verification JSON")
        );
        self.observe("handler-after-write", context, &changed("database-after"))?;
        Ok(Some(AuthResponse::json(
            200,
            &json!({"baseURL": context.base_url(), "original": INITIAL_URL}),
        )?))
    }
}

#[tokio::test]
async fn dispatch_shares_runtime_with_hooks_handler_and_database_callbacks() -> AuthResult<()> {
    for http in [false, true] {
        let shared = Shared::default();
        let config = config();
        let store = store(&config)?;
        let auth = AuthBuilder::new(config)
            .store_arc(store.clone())
            .rate_limit(better_auth_core::middleware::RateLimitConfig::new().enabled(false))
            .hooks(EndpointHooks {
                before: Some(Arc::new(shared.clone())),
                after: Some(Arc::new(shared.clone())),
            })
            .plugin(shared.clone())
            .build()
            .await?;
        let response = call(&auth, "/runtime-shared", http).await?;
        assert_eq!(response.status, 200);
        assert_eq!(
            response.body.field_value()?.json()?,
            Some(json!({"baseURL": changed("database-after"), "original": INITIAL_URL}))
        );
        assert_eq!(
            *lock(&shared.events)?,
            [
                "before",
                "plugin-before",
                "handler",
                "database-before",
                "database-after",
                "handler-after-write",
                "after"
            ]
        );
        let retained = lock(&shared.retained)?.clone().expect("Context retained");
        assert!(!std::ptr::eq(retained.as_ref(), auth.context()));
        assert_eq!(retained.base_url(), changed("after"));
        assert_eq!(auth.context().base_url(), INITIAL_URL);
        assert!(auth.context().current_request_context().is_none());
        assert!(better_auth_core::hooks::current_request_hook_context().is_none());
        let mut expected = empty_database();
        *expected.get_mut("verification").ok_or_else(|| {
            AuthError::internal("Expected the verification table in the database fixture")
        })? = json!([FieldValue::from(row().fields()?)
            .json()?
            .expect("Verification JSON")]);
        assert_eq!(snapshot(&store)?, expected);
    }
    Ok(())
}

#[derive(Clone)]
struct Failure {
    stage: &'static str,
    sentinel: FieldValue,
    events: Arc<Mutex<Vec<&'static str>>>,
    retained: Arc<Mutex<Option<Arc<AuthContext<S>>>>>,
}

impl Failure {
    fn observe(&self, stage: &'static str, context: &AuthContext<S>) -> AuthResult<()> {
        assert!(Arc::ptr_eq(
            &active(context),
            lock(&self.retained)?
                .as_ref()
                .expect("Before retained context")
        ));
        lock(&self.events)?.push(stage);
        if stage == self.stage {
            context.set_base_url(changed(stage));
            return Err(AuthError::from_thrown(self.sentinel.clone()));
        }
        Ok(())
    }
}
#[async_trait]
impl BeforeEndpointHook<S> for Failure {
    async fn before(
        &self,
        _: &AuthRequest,
        context: &AuthContext<S>,
    ) -> AuthResult<Option<BeforeRequestAction>> {
        *lock(&self.retained)? = Some(active(context));
        self.observe("before", context)?;
        Ok(None)
    }
}
#[async_trait]
impl AfterEndpointHook<S> for Failure {
    async fn after(
        &self,
        _: &AuthRequest,
        _: &mut AuthResponse,
        context: &AuthContext<S>,
    ) -> AuthResult<()> {
        self.observe("after", context)
    }
}
#[async_trait]
impl AuthPlugin<S> for Failure {
    fn name(&self) -> &'static str {
        "runtime-failure"
    }
    fn routes(&self) -> Vec<AuthRoute> {
        vec![AuthRoute::new(
            HttpMethod::Get,
            "/runtime-failure",
            "runtimeFailure",
        )]
    }
    async fn on_request(
        &self,
        _: &AuthRequest,
        context: &AuthContext<S>,
    ) -> AuthResult<Option<AuthResponse>> {
        self.observe("handler", context)?;
        Ok(Some(AuthResponse::json(200, &json!({"ok": true}))?))
    }
}

#[tokio::test]
async fn failed_callback_keeps_its_runtime_write_without_mutating_the_root() -> AuthResult<()> {
    for stage in ["before", "handler", "after"] {
        let sentinel = AuthError::from_status(
            "CONFLICT",
            FieldMap::from([("message".into(), "runtime failure".into())]).into(),
        )
        .raw_value()
        .cloned()
        .expect("APIError has native identity");
        let hook = Failure {
            stage,
            sentinel: sentinel.clone(),
            events: Arc::default(),
            retained: Arc::default(),
        };
        let config = config();
        let store = store(&config)?;
        let auth = AuthBuilder::new(config)
            .store_arc(store.clone())
            .rate_limit(better_auth_core::middleware::RateLimitConfig::new().enabled(false))
            .hooks(EndpointHooks {
                before: Some(Arc::new(hook.clone())),
                after: Some(Arc::new(hook.clone())),
            })
            .plugin(hook.clone())
            .build()
            .await?;
        let error = call(&auth, "/runtime-failure", false)
            .await
            .expect_err("Selected callback fails");
        assert!(
            error
                .raw_value()
                .expect("Original APIError")
                .strict_equals(&sentinel)
        );
        assert_eq!(
            lock(&hook.retained)?
                .as_ref()
                .expect("Context retained")
                .base_url(),
            changed(stage)
        );
        assert_eq!(auth.context().base_url(), INITIAL_URL);
        assert_eq!(
            *lock(&hook.events)?,
            if stage == "before" {
                vec!["before"]
            } else {
                vec!["before", "handler", "after"]
            }
        );
        assert!(auth.context().current_request_context().is_none());
        assert!(better_auth_core::hooks::current_request_hook_context().is_none());
        assert_eq!(snapshot(&store)?, empty_database());
    }
    Ok(())
}
