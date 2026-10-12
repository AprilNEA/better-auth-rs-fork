use async_trait::async_trait;
use better_auth::plugins::{
    AdminPlugin, DeviceAuthorizationPlugin, JwtPlugin, MagicLinkPlugin, MultiSessionPlugin,
    OAuthPlugin, OrganizationPlugin, SessionManagementPlugin,
    magic_link::{MagicLinkConfig, MagicLinkMessage, SendMagicLink},
    organization::{OrganizationConfig, OrganizationTeamsConfig},
};
use better_auth::server_api::EndpointInput;
use better_auth::{AuthConfig, AuthError, AuthResult, BetterAuth};
use better_auth_core::observability::{AfterEndpointHook, BeforeEndpointHook, EndpointHooks};
use better_auth_core::{
    ApiErrorClass, AuthContext, AuthRequest, AuthResponse, BeforeRequestAction, FieldValue,
    HttpMethod, ResponseBody, store::StatelessSchema as S,
};
use serde::Deserialize;
use serde_json::{Value, json};
use std::sync::{Arc, Mutex, MutexGuard};

struct Sender;
#[async_trait]
impl SendMagicLink for Sender {
    async fn send(&self, _: &MagicLinkMessage) -> AuthResult<()> {
        Ok(())
    }
}

#[derive(Clone, Default)]
struct Hooks(Arc<Mutex<Vec<Value>>>);
impl Hooks {
    fn trace(&self) -> AuthResult<MutexGuard<'_, Vec<Value>>> {
        self.0
            .lock()
            .map_err(|_| AuthError::internal("Endpoint hook trace lock poisoned"))
    }

    fn record(&self, phase: &str, request: &AuthRequest) -> AuthResult<()> {
        self.trace()?.push(json!({
            "phase":phase,"body":request.input_body()?,"query":request.query,
            "request":request.original_request().is_some(),
        }));
        Ok(())
    }
}
#[async_trait]
impl BeforeEndpointHook<S> for Hooks {
    async fn before(
        &self,
        req: &AuthRequest,
        _: &AuthContext<S>,
    ) -> AuthResult<Option<BeforeRequestAction>> {
        self.record("before", req)?;
        Ok(None)
    }
}
#[async_trait]
impl AfterEndpointHook<S> for Hooks {
    async fn after(
        &self,
        req: &AuthRequest,
        _: &mut AuthResponse,
        _: &AuthContext<S>,
    ) -> AuthResult<()> {
        self.record("after", req)
    }
}

#[derive(Deserialize)]
struct Case {
    path: String,
    method: String,
    kind: String,
    body: Option<Value>,
    query: Option<Value>,
    status: u16,
    result: Value,
}
#[derive(Deserialize)]
struct Oracle {
    records: Vec<Case>,
    trace: Vec<Value>,
}

// Better Auth 1.7.6: better-call/dist/validator.mjs and the registered endpoint options.
#[tokio::test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "The fixture compares complete validation responses and endpoint hook traces with assertions"
)]
async fn required_headers_preserve_schema_precedence_and_native_request_authority() -> AuthResult<()>
{
    let hooks = Hooks::default();
    let mut config = AuthConfig::new("headers-oracle-secret-at-least-32-characters");
    config.base_url = "http://headers.test".into();
    let auth = BetterAuth::stateless(config)
        .hooks(EndpointHooks {
            before: Some(Arc::new(hooks.clone())),
            after: Some(Arc::new(hooks.clone())),
        })
        .plugin(SessionManagementPlugin::new())
        .plugin(OAuthPlugin::new())
        .plugin(AdminPlugin::new())
        .plugin(OrganizationPlugin::with_config(OrganizationConfig {
            teams: OrganizationTeamsConfig {
                enabled: true,
                ..Default::default()
            },
            dynamic_access_control: true,
            ..Default::default()
        }))
        .plugin(MultiSessionPlugin::new())
        .plugin(MagicLinkPlugin::with_config(MagicLinkConfig {
            send_magic_link: Some(Arc::new(Sender)),
            ..Default::default()
        }))
        .plugin(JwtPlugin::new())
        .plugin(DeviceAuthorizationPlugin::new())
        .build()
        .await?;
    let oracle: Oracle =
        serde_json::from_str(include_str!("fixtures/required-headers-upstream.json"))?;
    let mut mismatches = Vec::new();
    for case in oracle.records {
        let method = if case.method == "GET" {
            HttpMethod::Get
        } else {
            HttpMethod::Post
        };
        let (status, body) = match auth
            .call_endpoint(
                method,
                &case.path,
                EndpointInput {
                    body: case.body,
                    query: case.query,
                    headers: (case.kind == "empty").then(Default::default),
                    request: (case.kind == "request")
                        .then(|| AuthRequest::new(HttpMethod::Get, "/source")),
                },
            )
            .await
        {
            Ok(response) => (response.status, response.body),
            Err(error) => {
                if case.kind != "empty" {
                    assert_eq!(error.status_value()?, FieldValue::from(400u16));
                    assert!(error.is_api_error_instance(ApiErrorClass::BetterCall));
                    assert!(!error.is_api_error_instance(ApiErrorClass::BetterAuth));
                }
                (
                    error.status_code()?.typed().copied()?,
                    ResponseBody::Native(error.body_value()?),
                )
            }
        };
        let bytes = body.bytes()?;
        let result: Value = if body.is_empty() {
            Value::Null
        } else {
            serde_json::from_slice(&bytes)?
        };
        if case.kind != "empty" {
            assert_eq!(
                bytes.as_ref(),
                serde_json::to_vec(&case.result)?.as_slice(),
                "{}/{}: complete validation response bytes",
                case.path,
                case.kind
            );
            let native = body.field_value()?.enumerable_fields()?;
            let expected = case
                .result
                .as_object()
                .ok_or_else(|| AuthError::internal("Expected validation error object"))?;
            assert_eq!(
                native.keys().collect::<Vec<_>>(),
                expected.keys().collect::<Vec<_>>(),
                "{}/{}: native validation property order",
                case.path,
                case.kind
            );
        }
        if (status, &result) != (case.status, &case.result) {
            mismatches.push(format!(
                "{}/{}: actual ({}, {}), expected ({}, {})",
                case.path, case.kind, status, result, case.status, case.result
            ));
        }
    }
    assert!(mismatches.is_empty(), "{}", mismatches.join("\n"));
    hooks.trace()?.clear();
    let status = match auth
        .call_endpoint(
            HttpMethod::Post,
            "/revoke-session",
            EndpointInput {
                body: Some(json!({"token":"fixture","unknown":7})),
                ..Default::default()
            },
        )
        .await
    {
        Ok(response) => response.status,
        Err(error) => error.status_code()?.typed().copied()?,
    };
    assert_eq!(status, 400);
    assert_eq!(*hooks.trace()?, oracle.trace);
    Ok(())
}
