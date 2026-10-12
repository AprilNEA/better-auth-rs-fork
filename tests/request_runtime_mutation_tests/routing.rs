//! Paired with contracts/request-runtime-url-routing.test.ts.

use super::*;
use better_auth_core::{
    TrustedValues, TrustedValuesResolver,
    api_error::{ApiErrorHandler, ApiErrorTask},
};

const ROUTING_ORIGIN: &str = "https://original.routing.test";
const DURING_REQUEST: &str = "http://during.routing.test/replaced";

#[derive(Clone, Default)]
struct Routing {
    observations: Arc<Mutex<Vec<Value>>>,
}

#[async_trait]
impl AuthPlugin<S> for Routing {
    fn name(&self) -> &'static str {
        "runtime-routing"
    }

    fn routes(&self) -> Vec<AuthRoute> {
        vec![AuthRoute::get("/routing-probe", "routingProbe")]
    }

    async fn on_http_request(
        &self,
        request: &AuthRequest,
        context: &AuthContext<S>,
    ) -> AuthResult<Option<AuthResponse>> {
        lock(&self.observations)?.push(json!({
            "phase": "onRequest",
            "baseURL": context.base_url(),
            "requestURL": request.url().expect("HTTP request has a URL").as_str(),
        }));
        context.set_base_url(DURING_REQUEST);
        Ok(None)
    }

    async fn on_request(
        &self,
        request: &AuthRequest,
        context: &AuthContext<S>,
    ) -> AuthResult<Option<AuthResponse>> {
        Ok(Some(AuthResponse::json(
            200,
            &json!({
                "baseURL": context.base_url(),
                "path": request.path,
                "optionURL": context.config.base_url.as_static(),
                "optionPath": context.config.base_path,
            }),
        )?))
    }

    async fn on_http_response(
        &self,
        _: &AuthRequest,
        _: &mut AuthResponse,
        context: &AuthContext<S>,
    ) -> AuthResult<Option<AuthResponse>> {
        lock(&self.observations)?.push(json!({
            "phase": "onResponse",
            "baseURL": context.base_url(),
        }));
        Ok(None)
    }
}

#[tokio::test]
async fn http_router_captures_current_root_url_pathname_before_request_hooks() -> AuthResult<()> {
    for (assigned, request_path) in [
        ("https://next.routing.test", "/routing-probe"),
        (
            "https://next.routing.test/root/../auth/",
            "/auth/routing-probe",
        ),
        (
            "https://next.routing.test/auth?next=/wrong#ignored",
            "/auth/routing-probe",
        ),
        (
            "https://next.routing.test?next=/wrong#ignored",
            "/routing-probe",
        ),
    ] {
        let config = config().base_url(ROUTING_ORIGIN);
        let store = store(&config)?;
        let capture = Routing::default();
        let auth = AuthBuilder::new(config)
            .store_arc(store.clone())
            .rate_limit(better_auth_core::middleware::RateLimitConfig::new().enabled(false))
            .plugin(capture.clone())
            .build()
            .await?;
        auth.context().set_base_url(assigned);
        let request_url = format!("{ROUTING_ORIGIN}{request_path}");
        let response = auth
            .handle_request(
                AuthRequest::new(HttpMethod::Get, request_path)
                    .with_url(request_url.parse().expect("Fixture URL")),
            )
            .await?;
        assert_eq!(response.status, 200);
        assert_eq!(
            response.body.json()?,
            Some(json!({
                "baseURL": DURING_REQUEST,
                "path": "/routing-probe",
                "optionURL": ROUTING_ORIGIN,
                "optionPath": BASE_PATH,
            }))
        );
        assert_eq!(
            *lock(&capture.observations)?,
            [
                json!({"phase": "onRequest", "baseURL": assigned, "requestURL": request_url}),
                json!({"phase": "onResponse", "baseURL": DURING_REQUEST}),
            ]
        );
        assert_eq!(auth.context().base_url(), assigned);
        assert_eq!(
            auth.context().config.base_url.as_static(),
            Some(ROUTING_ORIGIN)
        );
        assert_eq!(auth.context().config.base_path, BASE_PATH);
        assert_eq!(snapshot(&store)?, empty_database());
    }
    Ok(())
}

struct RoutingTrust {
    phase: &'static str,
    events: Arc<Mutex<Vec<String>>>,
}

#[async_trait]
impl TrustedValuesResolver for RoutingTrust {
    async fn resolve(&self, request: Option<&AuthRequest>) -> AuthResult<Vec<String>> {
        lock(&self.events)?.push(format!(
            "{}:{}",
            self.phase,
            if request.is_some() {
                "request"
            } else {
                "initial"
            }
        ));
        Ok(Vec::new())
    }
}

#[derive(Clone, Default)]
struct InvalidRouting {
    events: Arc<Mutex<Vec<String>>>,
}

#[async_trait]
impl AuthPlugin<S> for InvalidRouting {
    fn name(&self) -> &'static str {
        "runtime-routing-error"
    }

    fn routes(&self) -> Vec<AuthRoute> {
        vec![AuthRoute::get("/routing-probe", "routingProbe")]
    }

    async fn on_http_request(
        &self,
        _: &AuthRequest,
        _: &AuthContext<S>,
    ) -> AuthResult<Option<AuthResponse>> {
        lock(&self.events)?.push("onRequest".into());
        Ok(None)
    }

    async fn on_request(
        &self,
        _: &AuthRequest,
        _: &AuthContext<S>,
    ) -> AuthResult<Option<AuthResponse>> {
        lock(&self.events)?.push("handler".into());
        Ok(Some(AuthResponse::json(200, &json!({"ok": true}))?))
    }

    async fn on_http_response(
        &self,
        _: &AuthRequest,
        _: &mut AuthResponse,
        _: &AuthContext<S>,
    ) -> AuthResult<Option<AuthResponse>> {
        lock(&self.events)?.push("onResponse".into());
        Ok(None)
    }
}

impl ApiErrorHandler<S> for InvalidRouting {
    fn on_error(&self, _: &AuthError, _: &AuthContext<S>) -> AuthResult<Option<ApiErrorTask>> {
        lock(&self.events)?.push("router-error".into());
        Ok(None)
    }
}

#[tokio::test]
async fn invalid_root_url_fails_before_http_hooks_and_router_error_handling() -> AuthResult<()> {
    for assigned in ["", "/relative", "not a url", "https://[invalid"] {
        let capture = InvalidRouting::default();
        let mut config = config().base_url(ROUTING_ORIGIN);
        config.trusted_origins = Some(TrustedValues::Dynamic(Arc::new(RoutingTrust {
            phase: "origins",
            events: capture.events.clone(),
        })));
        config.account.account_linking.trusted_providers =
            Some(TrustedValues::Dynamic(Arc::new(RoutingTrust {
                phase: "providers",
                events: capture.events.clone(),
            })));
        let store = store(&config)?;
        let auth = AuthBuilder::new(config)
            .store_arc(store.clone())
            .rate_limit(better_auth_core::middleware::RateLimitConfig::new().enabled(false))
            .on_api_error(Arc::new(capture.clone()))
            .plugin(capture.clone())
            .build()
            .await?;
        assert_eq!(
            *lock(&capture.events)?,
            ["origins:initial", "providers:initial"]
        );
        lock(&capture.events)?.clear();
        auth.context().set_base_url(assigned);
        let request_path = format!("{BASE_PATH}/routing-probe");
        let error = auth
            .handle_request(
                AuthRequest::new(HttpMethod::Get, &request_path).with_url(
                    format!("{ROUTING_ORIGIN}{request_path}")
                        .parse()
                        .expect("Fixture URL"),
                ),
            )
            .await
            .expect_err("Invalid runtime URL fails before router construction");
        assert!(matches!(&error, AuthError::TypeError(_)));
        assert_eq!(error.to_string(), "Invalid URL");
        assert_eq!(
            *lock(&capture.events)?,
            ["origins:request", "providers:request"]
        );
        assert_eq!(auth.context().base_url(), assigned);
        assert_eq!(
            auth.context().config.base_url.as_static(),
            Some(ROUTING_ORIGIN)
        );
        assert_eq!(snapshot(&store)?, empty_database());
    }
    Ok(())
}
