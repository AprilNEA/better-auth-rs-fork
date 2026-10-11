#![expect(
    clippy::panic_in_result_fn,
    reason = "tests propagate setup failures and assert observable rate-limit behavior"
)]

use async_trait::async_trait;
use better_auth::__private_core::{
    AuthContext, AuthError, AuthPlugin, AuthRequest, AuthResponse, AuthResult, AuthRoute,
    BeforeRequestAction, HttpMethod, store::StatelessSchema,
};
use better_auth::middleware::{
    EndpointRateLimit, Middleware, RateLimitConfig, RateLimitDecision, RateLimitMiddleware,
    RateLimitStorage,
};
use better_auth::{AuthConfig, BetterAuth};
use serde_json::{Value, json};
use std::sync::{Arc, Mutex};

#[test]
fn environment_defaults_and_explicit_switches_use_separate_processes()
-> Result<(), Box<dyn std::error::Error>> {
    for environment in ["development", "production"] {
        let output = std::process::Command::new(std::env::current_exe()?)
            .args(["--exact", "environment_case", "--ignored"])
            .env("NODE_ENV", environment)
            .output()?;
        assert!(
            output.status.success(),
            "{environment}: {}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
    Ok(())
}

#[tokio::test]
#[ignore = "the parent runs this case in fresh development and production processes"]
async fn environment_case() -> AuthResult<()> {
    let production = std::env::var("NODE_ENV")
        .map_err(|error| AuthError::internal(error.to_string()))?
        == "production";
    for (index, configured) in [None, Some(false), Some(true)].into_iter().enumerate() {
        let limiter = RateLimitMiddleware::new(RateLimitConfig {
            window: Some(60.0),
            max_requests: Some(1.0),
            enabled: configured,
            ..Default::default()
        });
        let mut request = AuthRequest::new(HttpMethod::Get, "/rate-environment");
        let _ = request
            .headers
            .insert("x-forwarded-for".into(), format!("192.0.2.{}", index + 1));
        assert!(limiter.before_request(&request).await?.is_none());
        let response = limiter.before_request(&request).await?;
        assert_eq!(
            response.map(|response| response.status),
            configured.unwrap_or(production).then_some(429)
        );
    }
    Ok(())
}

#[derive(Default)]
struct Capture(Mutex<Vec<EndpointRateLimit>>);
#[async_trait]
impl RateLimitStorage for Capture {
    async fn consume(&self, _: &str, rule: EndpointRateLimit) -> AuthResult<RateLimitDecision> {
        self.0
            .lock()
            .map_err(|_| AuthError::internal("rate rule capture poisoned"))?
            .push(rule);
        Ok(RateLimitDecision {
            allowed: true,
            retry_after: None,
        })
    }
}

#[tokio::test]
async fn optional_defaults_reach_storage_as_concrete_rules() -> AuthResult<()> {
    for (window, maximum, expected) in [
        (None, None, (10.0, 100.0)),
        (Some(0.0), Some(0.0), (10.0, 100.0)),
        (Some(f64::NAN), Some(f64::NAN), (10.0, 100.0)),
        (Some(30.0), None, (30.0, 100.0)),
        (None, Some(7.0), (10.0, 7.0)),
        (Some(0.5), Some(1.5), (0.5, 1.5)),
    ] {
        let capture = Arc::new(Capture::default());
        let limiter = RateLimitMiddleware::new(RateLimitConfig {
            window,
            max_requests: maximum,
            enabled: Some(true),
            custom_storage: Some(capture.clone()),
            ..Default::default()
        });
        let mut request = AuthRequest::new(HttpMethod::Get, "/rate-options");
        let _ = request
            .headers
            .insert("x-forwarded-for".into(), "192.0.2.20".into());
        assert!(limiter.before_request(&request).await?.is_none());
        let rules = capture
            .0
            .lock()
            .map_err(|_| AuthError::internal("rate rule capture poisoned"))?;
        assert_eq!(
            rules
                .iter()
                .map(|rule| (rule.window, rule.max_requests))
                .collect::<Vec<_>>(),
            vec![expected]
        );
    }
    Ok(())
}

#[derive(Clone, Copy)]
enum StorageOutcome {
    Denied(Option<f64>),
    Allowed,
    Failed,
}

#[derive(Clone)]
struct HttpProbe {
    events: Arc<Mutex<Vec<Value>>>,
    outcome: StorageOutcome,
}

impl HttpProbe {
    fn record(&self, event: Value) -> AuthResult<()> {
        self.events
            .lock()
            .map_err(|_| AuthError::internal("rate HTTP event capture poisoned"))?
            .push(event);
        Ok(())
    }
}

#[async_trait]
impl RateLimitStorage for HttpProbe {
    async fn consume(&self, key: &str, rule: EndpointRateLimit) -> AuthResult<RateLimitDecision> {
        self.record(json!({
            "phase": "consume", "key": key,
            "window": rule.window, "max": rule.max_requests,
        }))?;
        match self.outcome {
            StorageOutcome::Denied(retry_after) => Ok(RateLimitDecision {
                allowed: false,
                retry_after,
            }),
            StorageOutcome::Allowed => Ok(RateLimitDecision {
                allowed: true,
                retry_after: None,
            }),
            StorageOutcome::Failed => Err(AuthError::internal("rate storage failed")),
        }
    }
}

#[async_trait]
impl AuthPlugin<StatelessSchema> for HttpProbe {
    fn name(&self) -> &'static str {
        "rate-limit-http-probe"
    }

    fn routes(&self) -> Vec<AuthRoute> {
        vec![AuthRoute::get("/rate-http", "rateHttp")]
    }

    async fn on_http_request(
        &self,
        _: &AuthRequest,
        _: &AuthContext<StatelessSchema>,
    ) -> AuthResult<Option<AuthResponse>> {
        self.record(json!({"phase": "http-request"}))?;
        Ok(None)
    }

    async fn before_request(
        &self,
        _: &AuthRequest,
        _: &AuthContext<StatelessSchema>,
    ) -> AuthResult<Option<BeforeRequestAction>> {
        self.record(json!({"phase": "before"}))?;
        Ok(None)
    }

    async fn on_request(
        &self,
        _: &AuthRequest,
        _: &AuthContext<StatelessSchema>,
    ) -> AuthResult<Option<AuthResponse>> {
        self.record(json!({"phase": "endpoint"}))?;
        Ok(Some(AuthResponse::json(200, &json!({"accepted": true}))?))
    }

    async fn after_request(
        &self,
        _: &AuthRequest,
        _: &mut AuthResponse,
        _: &AuthContext<StatelessSchema>,
    ) -> AuthResult<()> {
        self.record(json!({"phase": "after"}))?;
        Ok(())
    }

    async fn on_http_response(
        &self,
        _: &AuthRequest,
        _: &mut AuthResponse,
        _: &AuthContext<StatelessSchema>,
    ) -> AuthResult<Option<AuthResponse>> {
        self.record(json!({"phase": "http-response"}))?;
        Ok(None)
    }
}

fn assert_http_response(
    mut response: AuthResponse,
    status: u16,
    headers: &[(&str, &str)],
    body: &[u8],
) -> AuthResult<()> {
    for _ in 0..3 {
        assert!(!response.is_native());
        assert_eq!(response.status, status);
        assert_eq!(
            response
                .headers
                .iter()
                .map(|(name, value)| (name.as_str(), value.as_str()))
                .collect::<Vec<_>>(),
            headers
        );
        assert_eq!(response.body.bytes()?.as_ref(), body);
        response = response.into_http_response()?;
    }
    Ok(())
}

#[tokio::test]
async fn rate_limit_direct_and_http_boundaries_preserve_explicit_responses() -> AuthResult<()> {
    for (outcome, retry_after) in [
        (StorageOutcome::Denied(None), "7.5"),
        (StorageOutcome::Denied(Some(0.0)), "0"),
        (StorageOutcome::Denied(Some(2.25)), "2.25"),
        (StorageOutcome::Allowed, ""),
        (StorageOutcome::Failed, ""),
    ] {
        let probe = HttpProbe {
            events: Arc::new(Mutex::new(Vec::new())),
            outcome,
        };
        let rate_limit = RateLimitConfig {
            enabled: Some(true),
            window: Some(7.5),
            max_requests: Some(3.0),
            custom_storage: Some(Arc::new(probe.clone())),
            ..Default::default()
        };
        let auth = BetterAuth::stateless(
            AuthConfig::new("rate-http-secret-at-least-thirty-two-characters")
                .base_url("http://rate-http.test"),
        )
        .plugin(probe.clone())
        .rate_limit(rate_limit.clone())
        .build()
        .await?;
        let limiter = RateLimitMiddleware::from_context(rate_limit, auth.context(), Vec::new());
        for http in [false, true] {
            let mut request = AuthRequest::new(HttpMethod::Get, "/api/auth/rate-http");
            let _ = request
                .headers
                .insert("x-forwarded-for".into(), "192.0.2.45".into());
            let result = if http {
                auth.handle_request(request).await.map(Some)
            } else {
                limiter.before_request(&request).await
            };
            match outcome {
                StorageOutcome::Denied(_) => assert_http_response(
                    result?.ok_or_else(|| AuthError::internal("denied response missing"))?,
                    429,
                    &[("x-retry-after", retry_after)],
                    br#"{"message":"Too many requests. Please try again later."}"#,
                )?,
                StorageOutcome::Allowed if http => assert_http_response(
                    result?.ok_or_else(|| AuthError::internal("endpoint response missing"))?,
                    200,
                    &[("content-type", "application/json")],
                    br#"{"accepted":true}"#,
                )?,
                StorageOutcome::Allowed => assert!(result?.is_none()),
                StorageOutcome::Failed => assert!(
                    matches!(result, Err(AuthError::Internal(message)) if message == "rate storage failed")
                ),
            }
            let mut expected = vec![json!({
                "phase": "consume", "key": "192.0.2.45|/rate-http", "window": 7.5, "max": 3.0,
            })];
            if http && matches!(outcome, StorageOutcome::Allowed) {
                expected.extend(
                    [
                        "http-request",
                        "before",
                        "endpoint",
                        "after",
                        "http-response",
                    ]
                    .map(|phase| json!({"phase": phase})),
                );
            }
            let events = std::mem::take(
                &mut *probe
                    .events
                    .lock()
                    .map_err(|_| AuthError::internal("rate HTTP event capture poisoned"))?,
            );
            assert_eq!(events, expected);
        }
    }
    Ok(())
}
