#![cfg(feature = "axum")]
#![expect(
    clippy::panic_in_result_fn,
    reason = "The transport contract asserts exact status, body, callback counts, and raw error identity."
)]

use async_trait::async_trait;
use better_auth::{AuthConfig, BetterAuth, integrations::axum::AxumIntegration};
use better_auth_core::{
    AuthContext, AuthError, AuthPlugin, AuthRequest, AuthResponse, AuthResult, AuthRoute,
    FieldFunction, FieldMap, FieldValue, HttpMethod, LoggerConfig,
    api_error::{ApiErrorHandler, ApiErrorTask},
    store::StatelessSchema as S,
};
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};
use tower::ServiceExt;

#[derive(Clone)]
struct Failure {
    phase: &'static str,
    body: FieldValue,
    replacement: FieldValue,
    callbacks: Arc<AtomicUsize>,
}

#[async_trait]
impl AuthPlugin<S> for Failure {
    fn name(&self) -> &'static str {
        "http-conversion-ownership"
    }

    fn routes(&self) -> Vec<AuthRoute> {
        vec![AuthRoute::get("/conversion", "conversion")]
    }

    async fn on_http_request(
        &self,
        _: &AuthRequest,
        _: &AuthContext<S>,
    ) -> AuthResult<Option<AuthResponse>> {
        match self.phase {
            "source" => Err(AuthError::bad_request("source rejection")),
            "request" => Ok(Some(AuthResponse::json_value(None, self.body.clone()))),
            _ => Ok(None),
        }
    }

    async fn on_request(
        &self,
        _: &AuthRequest,
        _: &AuthContext<S>,
    ) -> AuthResult<Option<AuthResponse>> {
        if self.phase == "error-body" {
            return Err(AuthError::from_status("BAD_REQUEST", self.body.clone()));
        }
        if self.phase == "callback-response" {
            return Err(AuthError::internal("endpoint source"));
        }
        Ok(Some(AuthResponse::new(200)))
    }

    async fn on_http_response(
        &self,
        _: &AuthRequest,
        _: &mut AuthResponse,
        _: &AuthContext<S>,
    ) -> AuthResult<Option<AuthResponse>> {
        Ok((self.phase == "response").then(|| AuthResponse::json_value(None, self.body.clone())))
    }
}

impl ApiErrorHandler<S> for Failure {
    fn on_error(&self, error: &AuthError, _: &AuthContext<S>) -> AuthResult<Option<ApiErrorTask>> {
        self.callbacks.fetch_add(1, Ordering::SeqCst);
        if self.phase == "error-body" {
            assert!(
                error
                    .raw_value()
                    .is_some_and(|raw| raw.strict_equals(&self.replacement))
            );
        }
        if self.phase == "callback-response" {
            return Err(AuthError::from_status("BAD_REQUEST", self.body.clone()));
        }
        Ok(None)
    }
}

#[tokio::test]
async fn axum_preserves_source_rejections_and_does_not_retry_failed_http_conversion()
-> AuthResult<()> {
    for phase in [
        "source",
        "request",
        "response",
        "error-body",
        "callback-response",
    ] {
        let source_calls = Arc::new(AtomicUsize::new(0));
        let replacement_calls = Arc::new(AtomicUsize::new(0));
        let observed = replacement_calls.clone();
        let replacement: FieldValue = FieldMap::from([(
            "toJSON".into(),
            FieldFunction::contextual(move |_, _| {
                observed.fetch_add(1, Ordering::SeqCst);
                Ok("replacement must not become a new response".into())
            })
            .into(),
        )])
        .into();
        let cause = replacement.clone();
        let observed = source_calls.clone();
        let failure = Failure {
            phase,
            body: FieldMap::from([(
                "toJSON".into(),
                FieldFunction::contextual(move |_, _| {
                    observed.fetch_add(1, Ordering::SeqCst);
                    Err(AuthError::from_thrown(cause.clone()))
                })
                .into(),
            )])
            .into(),
            callbacks: Arc::new(AtomicUsize::new(0)),
            replacement: replacement.clone(),
        };
        let mut config = AuthConfig::new("http-conversion-ownership-at-least-32-characters")
            .base_url("http://conversion.test");
        config.logger = LoggerConfig {
            disabled: Some(true),
            ..Default::default()
        }
        .into();
        config.experimental.instrumentation.enabled = false;
        let auth = Arc::new(
            BetterAuth::stateless(config)
                .plugin(failure.clone())
                .on_api_error(Arc::new(failure.clone()))
                .build()
                .await?,
        );

        let direct = auth
            .handle_request(AuthRequest::new(HttpMethod::Get, "/api/auth/conversion"))
            .await;
        if phase == "error-body" {
            let response = direct?;
            assert_eq!(response.status, 500);
            assert!(response.body.bytes()?.is_empty());
        } else {
            let error = direct.err().ok_or_else(|| {
                AuthError::internal("The direct caller must receive the original failure")
            })?;
            if phase == "source" {
                assert!(
                    matches!(error, AuthError::BadRequest(message) if message == "source rejection")
                );
            } else {
                assert!(
                    error
                        .raw_value()
                        .is_some_and(|raw| raw.strict_equals(&replacement))
                );
            }
        }
        source_calls.store(0, Ordering::SeqCst);
        failure.callbacks.store(0, Ordering::SeqCst);
        let response = auth
            .clone()
            .axum_router()
            .with_state(auth)
            .oneshot(
                axum::http::Request::builder()
                    .uri("/conversion")
                    .body(axum::body::Body::empty())
                    .map_err(|error| AuthError::internal(error.to_string()))?,
            )
            .await
            .unwrap_or_else(|error| match error {});
        assert_eq!(
            response.status().as_u16(),
            if phase == "source" { 400 } else { 500 }
        );
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .map_err(|error| AuthError::internal(error.to_string()))?;
        if phase == "source" {
            assert_eq!(
                serde_json::from_slice::<serde_json::Value>(&bytes)
                    .map_err(|error| AuthError::internal(error.to_string()))?,
                serde_json::json!({"message":"source rejection"})
            );
        } else if phase == "error-body" {
            assert!(bytes.is_empty());
        } else {
            assert_eq!(bytes.as_ref(), b"Internal server error");
        }
        assert_eq!(
            source_calls.load(Ordering::SeqCst),
            usize::from(phase != "source")
        );
        assert_eq!(replacement_calls.load(Ordering::SeqCst), 0);
        assert_eq!(
            failure.callbacks.load(Ordering::SeqCst),
            usize::from(matches!(phase, "error-body" | "callback-response"))
        );
    }
    Ok(())
}
