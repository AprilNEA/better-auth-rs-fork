#![expect(
    clippy::panic_in_result_fn,
    reason = "The query contract asserts complete responses and hook order while propagating setup errors."
)]

use std::sync::{Arc, Mutex};

use better_auth::{AuthConfig, BetterAuth, server_api::EndpointInput};
use better_auth_core::{
    AuthContext, AuthError, AuthPlugin, AuthRequest, AuthResponse, AuthResult, AuthRoute,
    BeforeRequestAction, HttpMethod, hooks::current_request_hook_context,
    middleware::RateLimitConfig, store::StatelessSchema,
};
use serde_json::{Value, json};

#[path = "request_query_tests/native.rs"]
mod native;

fn required<T>(value: Option<T>) -> AuthResult<T> {
    value.ok_or_else(|| AuthError::internal("Required query contract observation is absent"))
}

fn lock<T>(value: &Mutex<T>) -> AuthResult<std::sync::MutexGuard<'_, T>> {
    value
        .lock()
        .map_err(|_| AuthError::internal("Query contract lock is poisoned"))
}

struct Probe(Arc<Mutex<Vec<Value>>>);
#[async_trait::async_trait]
impl AuthPlugin<StatelessSchema> for Probe {
    fn name(&self) -> &'static str {
        "query-probe"
    }
    fn routes(&self) -> Vec<AuthRoute> {
        vec![
            AuthRoute::get("/probe", "probe")
                .query_validator(better_auth_core::query::session_query),
        ]
    }
    async fn before_request(
        &self,
        req: &AuthRequest,
        _: &AuthContext<StatelessSchema>,
    ) -> AuthResult<Option<BeforeRequestAction>> {
        lock(&self.0)?.push(json!({"phase":"before","query":req.input_query()?}));
        Ok(None)
    }
    async fn on_request(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<StatelessSchema>,
    ) -> AuthResult<Option<AuthResponse>> {
        let endpoint = better_auth::plugins::endpoint_context::EndpointContext::new(
            Some(req),
            better_auth_core::FieldValue::Null,
            ctx,
        );
        AuthResponse::json(
            200,
            &json!({
                "query": req.input_query()?,
                "scope": required(current_request_hook_context())?.query.json()?,
                "original": endpoint.request.map(|request| request.query.clone()),
            }),
        )
        .map(Some)
    }
    async fn after_request(
        &self,
        req: &AuthRequest,
        _: &mut AuthResponse,
        _: &AuthContext<StatelessSchema>,
    ) -> AuthResult<()> {
        lock(&self.0)?.push(json!({"phase":"after","query":req.input_query()?}));
        Ok(())
    }
}

#[tokio::test]
async fn validated_query_keeps_original_http_and_native_request_provenance()
-> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let trace = Arc::new(Mutex::new(Vec::new()));
    let auth = BetterAuth::stateless(
        AuthConfig::new("query-scope-secret-with-at-least-32-characters")
            .base_url("http://localhost:3000"),
    )
    .rate_limit(RateLimitConfig::new().enabled(false))
    .plugin(Probe(trace.clone()))
    .build()
    .await?;
    let raw = json!({"disableRefresh":"false","unknown":"raw"});
    let mut request = AuthRequest::new(HttpMethod::Get, "/api/auth/probe")
        .with_url("http://localhost:3000/api/auth/probe?disableRefresh=false&unknown=raw".parse()?);
    request.query = Some(raw.clone());
    let response = auth.handle_request(request).await?;
    assert_eq!(
        serde_json::from_slice::<Value>(&response.body.bytes()?)?,
        json!({"query":{"disableRefresh":true},"scope":{"disableRefresh":true},"original":raw})
    );
    assert_eq!(
        *lock(&trace)?,
        vec![
            json!({"phase":"before","query":raw}),
            json!({"phase":"after","query":raw})
        ]
    );
    for present in [false, true] {
        lock(&trace)?.clear();
        let mut original = AuthRequest::new(HttpMethod::Get, "/original");
        original.query = Some(json!({"transport":"original"}));
        let response = auth
            .call_endpoint(
                HttpMethod::Get,
                "/probe",
                EndpointInput {
                    query: Some(raw.clone()),
                    request: present.then_some(original),
                    ..Default::default()
                },
            )
            .await?;
        let body: Value = serde_json::from_slice(&response.body.bytes()?)?;
        assert_eq!(body.get("query"), Some(&json!({"disableRefresh":true})));
        assert_eq!(required(body.get("scope"))?, required(body.get("query"))?);
        assert_eq!(
            required(body.get("original"))?,
            &if present {
                json!({"transport":"original"})
            } else {
                Value::Null
            }
        );
        assert_eq!(
            *lock(&trace)?,
            vec![
                json!({"phase":"before","query":raw}),
                json!({"phase":"after","query":raw})
            ]
        );
    }
    Ok(())
}
