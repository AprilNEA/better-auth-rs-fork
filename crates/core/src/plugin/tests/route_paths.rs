#![expect(
    clippy::expect_used,
    clippy::panic_in_result_fn,
    reason = "The dispatch regression asserts complete path observations; tracing callbacks cannot return lock errors."
)]

use async_trait::async_trait;
use std::{
    collections::HashMap,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
};
use tracing::{
    Event, Metadata, Subscriber,
    field::{Field, Visit},
    instrument::WithSubscriber,
    span::{Attributes, Id, Record},
};

use crate::{
    AuthContext, AuthError, AuthRequest, AuthResponse, AuthResult, AuthRoute, BeforeRequestAction,
    HttpMethod,
    endpoint_dispatch::EndpointDispatcher,
    hooks::{
        RequestHookContext, current_request_hook_context, set_request_hook_route,
        with_request_hook_context_value,
    },
    observability::{AfterEndpointHook, BeforeEndpointHook, EndpointHooks},
    store::{EphemeralStore, StatelessSchema},
};

#[derive(Debug)]
struct Observation {
    phase: &'static str,
    request: String,
    scope: Option<String>,
    snapshot: String,
    params: HashMap<String, String>,
    http: bool,
    original: Option<String>,
}

#[derive(Clone, Default)]
struct Observe(Arc<Mutex<Vec<Observation>>>);

impl Observe {
    fn record(&self, phase: &'static str, request: &AuthRequest) -> AuthResult<()> {
        let scope = current_request_hook_context()
            .ok_or_else(|| AuthError::internal("Expected endpoint hook context"))?;
        self.0
            .lock()
            .map_err(|_| AuthError::internal("Path observation lock poisoned"))?
            .push(Observation {
                phase,
                request: request.path().into(),
                scope: scope.path,
                snapshot: scope.request.path().into(),
                params: scope.params,
                http: scope.is_http,
                original: request
                    .original_request()
                    .map(|request| request.path().into()),
            });
        Ok(())
    }
}

#[async_trait]
impl BeforeEndpointHook<StatelessSchema> for Observe {
    async fn before(
        &self,
        request: &AuthRequest,
        _: &AuthContext<StatelessSchema>,
    ) -> AuthResult<Option<BeforeRequestAction>> {
        self.record("before", request)?;
        Ok(None)
    }
}

#[async_trait]
impl AfterEndpointHook<StatelessSchema> for Observe {
    async fn after(
        &self,
        request: &AuthRequest,
        _: &mut AuthResponse,
        _: &AuthContext<StatelessSchema>,
    ) -> AuthResult<()> {
        self.record("after", request)
    }
}

#[derive(Default)]
struct TraceState {
    sequence: AtomicU64,
    fields: Mutex<Vec<(String, String)>>,
}

#[derive(Clone, Default)]
struct Trace(Arc<TraceState>);

impl Visit for Trace {
    fn record_str(&mut self, field: &Field, value: &str) {
        if matches!(field.name(), "otel.name" | "http.route") {
            self.0
                .fields
                .lock()
                .expect("Trace lock")
                .push((field.name().into(), value.into()));
        }
    }

    fn record_debug(&mut self, _: &Field, _: &dyn std::fmt::Debug) {}
}

impl Subscriber for Trace {
    fn enabled(&self, metadata: &Metadata<'_>) -> bool {
        metadata.target() == "better-auth"
    }

    fn new_span(&self, attributes: &Attributes<'_>) -> Id {
        attributes.record(&mut self.clone());
        Id::from_u64(self.0.sequence.fetch_add(1, Ordering::Relaxed) + 1)
    }

    fn record(&self, _: &Id, values: &Record<'_>) {
        values.record(&mut self.clone());
    }

    fn record_follows_from(&self, _: &Id, _: &Id) {}
    fn event(&self, _: &Event<'_>) {}
    fn enter(&self, _: &Id) {}
    fn exit(&self, _: &Id) {}
}

#[tokio::test]
async fn dispatch_uses_upstream_templates_without_rewriting_http_request_paths() -> AuthResult<()> {
    let config = crate::test_store::test_config();
    let context = AuthContext::new(config.clone(), Arc::new(EphemeralStore::new(config)));
    for mode in ["native", "http", "server-only"] {
        let http = mode == "http";
        let server_only = mode == "server-only";
        let observations = Observe::default();
        let validator = observations.clone();
        let route = if server_only {
            AuthRoute::server_only(HttpMethod::Get, "pathProbe")
        } else {
            AuthRoute::get("/items/{group}/{id}", "pathProbe")
        }
        .body_validator(move |request| {
            validator.record("validate", request)?;
            request.unvalidated_input()
        });
        assert_eq!(
            route.path,
            if server_only {
                "/"
            } else {
                "/items/{group}/{id}"
            }
        );
        assert_eq!(
            route.matches(&HttpMethod::Get, "/items/team/one"),
            !server_only
        );
        let dispatcher = EndpointDispatcher::new(
            Arc::new(Vec::new()),
            EndpointHooks {
                before: Some(Arc::new(observations.clone())),
                after: Some(Arc::new(observations.clone())),
            },
            [route.clone()],
        );
        let trace = Trace::default();
        let handler_observations = observations.clone();
        let handler = move |request: AuthRequest| async move {
            handler_observations.record("handler", &request)?;
            AuthResponse::json(200, &serde_json::json!({"ok": true}))
        };
        let response = async {
            let mut request = AuthRequest::new(HttpMethod::Get, "/items/team/one");
            if http {
                let mut scope = RequestHookContext::from_request(&request)?;
                scope.is_http = true;
                with_request_hook_context_value(scope, async {
                    set_request_hook_route(request.path(), Some(&route));
                    dispatcher
                        .run(&mut request, true, &context, None, handler)
                        .await
                })
                .await
            } else {
                dispatcher
                    .native(request, route.clone(), &context, handler)
                    .await
            }
        }
        .with_subscriber(trace.clone())
        .await?;
        assert_eq!(response.status, 200);
        let observations = observations
            .0
            .lock()
            .map_err(|_| AuthError::internal("Path observation lock poisoned"))?;
        assert_eq!(
            observations
                .iter()
                .map(|entry| entry.phase)
                .collect::<Vec<_>>(),
            ["before", "validate", "handler", "after"]
        );
        for entry in observations.iter() {
            let (request_path, scope_path) = if server_only && entry.phase == "handler" {
                ("virtual:", Some("virtual:"))
            } else if server_only {
                ("/", None)
            } else if http {
                ("/items/team/one", Some("/items/:group/:id"))
            } else {
                ("/items/:group/:id", Some("/items/:group/:id"))
            };
            assert_eq!(entry.request, request_path, "{mode} {}", entry.phase);
            assert_eq!(entry.snapshot, request_path, "{mode} {}", entry.phase);
            assert_eq!(entry.scope.as_deref(), scope_path, "{mode} {}", entry.phase);
            assert_eq!(entry.http, http);
            assert_eq!(
                entry.params,
                if http {
                    HashMap::from([("group".into(), "team".into()), ("id".into(), "one".into())])
                } else {
                    HashMap::new()
                }
            );
            if entry.phase == "handler" {
                assert_eq!(entry.original.as_deref(), http.then_some("/items/team/one"));
            }
        }
        let route_path = if server_only {
            "/:virtual"
        } else {
            "/items/:group/:id"
        };
        let mut names = Vec::new();
        if !http {
            names.push(format!("GET {route_path}"));
        }
        names.extend([
            format!("hook before {route_path} user"),
            format!("handler {route_path}"),
            format!("hook after {route_path} user"),
        ]);
        let fields = trace.0.fields.lock().expect("Trace lock");
        assert_eq!(
            fields
                .iter()
                .filter(|(key, _)| key == "otel.name")
                .map(|(_, value)| value)
                .collect::<Vec<_>>(),
            names.iter().collect::<Vec<_>>()
        );
        assert_eq!(
            fields
                .iter()
                .filter(|(key, _)| key == "http.route")
                .map(|(_, value)| value.as_str())
                .collect::<Vec<_>>(),
            vec![route_path; names.len()]
        );
    }
    Ok(())
}
