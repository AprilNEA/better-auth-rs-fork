use super::*;
use std::sync::{OnceLock, Weak};

#[derive(Clone, Copy, Debug)]
enum Dispatch {
    RootApi,
    Explicit,
}

#[derive(Clone)]
struct Nested {
    dispatch: Dispatch,
    failure: bool,
    sentinel: FieldValue,
    auth: Arc<OnceLock<Weak<BetterAuth<S>>>>,
    parent: Arc<Mutex<Option<Arc<AuthContext<S>>>>>,
    child: Arc<Mutex<Option<Arc<AuthContext<S>>>>>,
    events: Arc<Mutex<Vec<&'static str>>>,
}

impl Nested {
    fn child(&self, context: &AuthContext<S>) -> AuthResult<AuthResponse> {
        lock(&self.events)?.push("child-handler");
        *lock(&self.child)? = Some(active(context));
        assert_path("/runtime-child");
        let before = context.base_url();
        context.set_base_url(changed("child"));
        if self.failure {
            return Err(AuthError::from_thrown(self.sentinel.clone()));
        }
        AuthResponse::json(
            200,
            &json!({ "before": before, "after": context.base_url() }),
        )
    }

    async fn parent(&self, context: &AuthContext<S>) -> AuthResult<AuthResponse> {
        let parent = active(context);
        *lock(&self.parent)? = Some(parent.clone());
        context.set_base_url(changed("parent"));
        let child = match self.dispatch {
            Dispatch::RootApi => {
                let auth = self
                    .auth
                    .get()
                    .and_then(Weak::upgrade)
                    .expect("Root API is bound");
                call(&auth, "/runtime-child", false).await
            }
            Dispatch::Explicit => {
                context
                    .dispatch_native(
                        Default::default(),
                        AuthRoute::new(HttpMethod::Get, "/runtime-child", "runtimeChild"),
                        None,
                        None,
                        |_, child| async move { self.child(&child) },
                    )
                    .await
            }
        };
        let result = match child {
            Ok(response) => {
                assert!(!self.failure);
                assert_eq!(response.status, 200);
                response
                    .body
                    .field_value()?
                    .json()?
                    .expect("Child result is JSON")
            }
            Err(error) => {
                assert!(self.failure);
                assert!(
                    error
                        .raw_value()
                        .expect("Child APIError identity")
                        .strict_equals(&self.sentinel)
                );
                Value::Null
            }
        };
        assert!(Arc::ptr_eq(&active(context), &parent));
        assert_path("/runtime-parent");
        lock(&self.events)?.push("parent-restored");
        AuthResponse::json(
            200,
            &json!({
                "result": result, "failed": self.failure, "baseURL": context.base_url(),
            }),
        )
    }
}

#[async_trait]
impl BeforeEndpointHook<S> for Nested {
    async fn before(
        &self,
        request: &AuthRequest,
        _: &AuthContext<S>,
    ) -> AuthResult<Option<BeforeRequestAction>> {
        if request.path() == "/runtime-child" {
            lock(&self.events)?.push("child-before");
        }
        Ok(None)
    }
}

#[async_trait]
impl AfterEndpointHook<S> for Nested {
    async fn after(
        &self,
        request: &AuthRequest,
        response: &mut AuthResponse,
        context: &AuthContext<S>,
    ) -> AuthResult<()> {
        if request.path() != "/runtime-child" {
            return Ok(());
        }
        lock(&self.events)?.push("child-after");
        assert!(Arc::ptr_eq(
            &active(context),
            lock(&self.child)?.as_ref().expect("Child context retained")
        ));
        assert_eq!(context.base_url(), changed("child"));
        if self.failure {
            assert!(response.body.field_value()?.strict_equals(&self.sentinel));
        }
        Ok(())
    }
}

#[async_trait]
impl AuthPlugin<S> for Nested {
    fn name(&self) -> &'static str {
        "runtime-nested"
    }

    fn routes(&self) -> Vec<AuthRoute> {
        vec![
            AuthRoute::new(HttpMethod::Get, "/runtime-parent", "runtimeParent"),
            AuthRoute::new(HttpMethod::Get, "/runtime-child", "runtimeChild"),
        ]
    }

    async fn on_request(
        &self,
        request: &AuthRequest,
        context: &AuthContext<S>,
    ) -> AuthResult<Option<AuthResponse>> {
        match request.path() {
            "/runtime-parent" => self.parent(context).await.map(Some),
            "/runtime-child" => self.child(context).map(Some),
            _ => Ok(None),
        }
    }
}

#[tokio::test]
async fn nested_dispatch_forks_from_the_selected_source_and_restores_parent_after_errors()
-> AuthResult<()> {
    for dispatch in [Dispatch::RootApi, Dispatch::Explicit] {
        for failure in [false, true] {
            let sentinel = AuthError::from_status(
                "CONFLICT",
                FieldMap::from([("message".into(), "child failed".into())]).into(),
            )
            .raw_value()
            .cloned()
            .expect("APIError has native identity");
            let nested = Nested {
                dispatch,
                failure,
                sentinel,
                auth: Arc::default(),
                parent: Arc::default(),
                child: Arc::default(),
                events: Arc::default(),
            };
            let config = config();
            let store = store(&config)?;
            let auth = Arc::new(
                AuthBuilder::new(config)
                    .store_arc(store.clone())
                    .rate_limit(better_auth_core::middleware::RateLimitConfig::new().enabled(false))
                    .hooks(EndpointHooks {
                        before: Some(Arc::new(nested.clone())),
                        after: Some(Arc::new(nested.clone())),
                    })
                    .plugin(nested.clone())
                    .build()
                    .await?,
            );
            assert!(nested.auth.set(Arc::downgrade(&auth)).is_ok());
            let response = call(&auth, "/runtime-parent", false).await?;
            let before = match dispatch {
                Dispatch::RootApi => INITIAL_URL.to_owned(),
                Dispatch::Explicit => changed("parent"),
            };
            assert_eq!(response.status, 200);
            assert_eq!(
                response.body.field_value()?.json()?,
                Some(json!({
                    "result": if failure { Value::Null } else { json!({ "before": before, "after": changed("child") }) },
                    "failed": failure,
                    "baseURL": changed("parent"),
                })),
                "{dispatch:?}/{failure}"
            );
            let child = lock(&nested.child)?
                .clone()
                .expect("Child context retained");
            let parent = lock(&nested.parent)?
                .clone()
                .expect("Parent context retained");
            assert!(!Arc::ptr_eq(&child, &parent));
            assert!(!std::ptr::eq(child.as_ref(), auth.context()));
            assert_eq!(
                *lock(&nested.events)?,
                [
                    "child-before",
                    "child-handler",
                    "child-after",
                    "parent-restored"
                ]
            );
            assert_root(&auth, &store)?;
        }
    }
    Ok(())
}
