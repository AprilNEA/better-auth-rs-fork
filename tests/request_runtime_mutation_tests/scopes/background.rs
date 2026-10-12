use super::*;
use better_auth::plugins::endpoint_context::{EndpointContext, OwnedEndpointContext};
use better_auth_core::background::{
    BackgroundFuture, BackgroundTask, BackgroundTasks, run_or_await,
};
use std::time::Duration;
use tokio::sync::Notify;

#[derive(Default)]
struct State {
    release: Notify,
    retained: Mutex<Option<Arc<AuthContext<S>>>>,
    events: Mutex<Vec<&'static str>>,
    observations: Mutex<Vec<Value>>,
    tasks: Mutex<Vec<BackgroundTask>>,
}

#[derive(Clone, Default)]
struct Background(Arc<State>);

#[async_trait]
impl AuthPlugin<S> for Background {
    fn name(&self) -> &'static str {
        "runtime-background"
    }

    fn routes(&self) -> Vec<AuthRoute> {
        vec![AuthRoute::new(
            HttpMethod::Get,
            "/runtime-background",
            "runtimeBackground",
        )]
    }

    async fn on_request(
        &self,
        request: &AuthRequest,
        context: &AuthContext<S>,
    ) -> AuthResult<Option<AuthResponse>> {
        let retained = active(context);
        *lock(&self.0.retained)? = Some(retained.clone());
        context.set_base_url(changed("handler"));
        let snapshot = context.base_url();
        let endpoint: OwnedEndpointContext<S> = EndpointContext::native(
            Some(request),
            request.original_request(),
            request.input_field_value()?,
            context,
        )
        .to_owned();
        let state = self.0.clone();
        run_or_await(
            Some(BackgroundFuture::new(async move {
                lock(&state.events)?.push("background-start");
                state.release.notified().await;
                let endpoint = endpoint.as_endpoint();
                let current = endpoint
                    .auth
                    .current_request_context()
                    .expect("Background keeps runtime scope");
                let scope =
                    current_request_hook_context().expect("Background keeps endpoint scope");
                assert_eq!(scope.path.as_deref(), endpoint.path);
                assert_eq!(scope.path.as_deref(), Some("/runtime-background"));
                assert!(scope.body.strict_equals(&endpoint.body));
                assert!(!scope.is_http);
                assert!(endpoint.request.is_none());
                assert_eq!(endpoint.auth.base_url(), changed("after"));
                lock(&state.observations)?.push(json!({
                    "sameContext": Arc::ptr_eq(&current, &retained),
                    "baseURL": current.base_url(), "snapshot": snapshot,
                }));
                lock(&state.events)?.push("background-resume");
                current.set_base_url(changed("background"));
                assert_eq!(endpoint.auth.base_url(), changed("background"));
                Ok(())
            })),
            context.config.advanced.background_tasks.as_ref(),
            context.logger(),
        )
        .await?;
        lock(&self.0.events)?.push("handler-return");
        AuthResponse::json(200, &json!({ "baseURL": context.base_url() })).map(Some)
    }
}

#[async_trait]
impl AfterEndpointHook<S> for Background {
    async fn after(
        &self,
        _: &AuthRequest,
        _: &mut AuthResponse,
        context: &AuthContext<S>,
    ) -> AuthResult<()> {
        lock(&self.0.events)?.push("after");
        assert!(Arc::ptr_eq(
            &active(context),
            lock(&self.0.retained)?
                .as_ref()
                .expect("Handler retains runtime")
        ));
        context.set_base_url(changed("after"));
        Ok(())
    }
}

#[tokio::test]
async fn owned_background_callback_observes_later_writes_after_the_response() -> AuthResult<()> {
    let background = Background::default();
    let mut config = config();
    let scheduler = background.0.clone();
    config.advanced.background_tasks = Some(BackgroundTasks::new(move |task| {
        lock(&scheduler.events)?.push("scheduled");
        lock(&scheduler.tasks)?.push(task);
        Ok(())
    }));
    let store = store(&config)?;
    let auth = AuthBuilder::new(config)
        .store_arc(store.clone())
        .rate_limit(better_auth_core::middleware::RateLimitConfig::new().enabled(false))
        .hooks(EndpointHooks {
            before: None,
            after: Some(Arc::new(background.clone())),
        })
        .plugin(background.clone())
        .build()
        .await?;
    let response = tokio::time::timeout(
        Duration::from_secs(5),
        call(&auth, "/runtime-background", false),
    )
    .await;
    lock(&background.0.events)?.push("response");
    let retained = lock(&background.0.retained)?.clone();
    let after_response = retained.as_ref().map(|context| context.base_url());
    let root_after_response = auth.context().base_url();
    let tasks = std::mem::take(&mut *lock(&background.0.tasks)?);
    let task_count = tasks.len();
    background.0.release.notify_one();
    tokio::time::timeout(Duration::from_secs(5), async {
        for task in tasks {
            assert_eq!(
                task.await
                    .expect("Background contract task completed")
                    .expect("Background contract application task succeeded"),
                better_auth_core::FieldValue::Undefined
            );
        }
    })
    .await
    .map_err(|_| {
        AuthError::internal("Background callbacks did not finish within 5 seconds after release")
    })?;
    let response = response.map_err(|_| {
        AuthError::internal(
            "Endpoint did not return within 5 seconds while its background callback was pending",
        )
    })??;
    assert_eq!(response.status, 200);
    assert_eq!(
        response.body.field_value()?.json()?,
        Some(json!({ "baseURL": changed("handler") }))
    );
    assert_eq!(after_response, Some(changed("after")));
    assert_eq!(root_after_response, INITIAL_URL);
    assert_eq!(task_count, 1);
    assert_eq!(
        *lock(&background.0.observations)?,
        [json!({
            "sameContext": true, "baseURL": changed("after"), "snapshot": changed("handler"),
        })]
    );
    assert_eq!(
        *lock(&background.0.events)?,
        [
            "background-start",
            "scheduled",
            "handler-return",
            "after",
            "response",
            "background-resume"
        ]
    );
    assert_eq!(
        retained.expect("Handler retains runtime").base_url(),
        changed("background")
    );
    assert_root(&auth, &store)?;
    Ok(())
}
