#![allow(
    clippy::expect_used,
    reason = "Fixture setup and response assertions require successful fallible construction."
)]
#![expect(
    clippy::panic_in_result_fn,
    reason = "Native endpoint contracts assert complete hook observations and propagate setup errors."
)]

use async_trait::async_trait;
use better_auth::plugins::email_otp::EmailOtpCallbacks;
use better_auth::plugins::{EmailOtpPlugin, EmailOtpType, JwtPlugin, TwoFactorPlugin};
use better_auth::{AuthConfig, AuthError, AuthResult, BetterAuth};
use better_auth_core::endpoint_input::EndpointInputPatch;
use better_auth_core::observability::{AfterEndpointHook, BeforeEndpointHook, EndpointHooks};
use better_auth_core::{
    AuthContext, AuthRequest, AuthResponse, BeforeRequestAction, NativeRequest,
    store::StatelessSchema as S,
};
use serde_json::{Value, json};
use std::sync::{Arc, Mutex};

#[path = "native_endpoint_tests/http_json_router.rs"]
mod http_json_router;

#[path = "native_endpoint_tests/body_context.rs"]
mod body_context;

#[path = "native_endpoint_tests/update_user_session.rs"]
mod update_user_session;

#[derive(Default)]
struct State {
    mode: String,
    events: Vec<Value>,
}
#[derive(Clone, Default)]
struct Hooks(Arc<Mutex<State>>);
impl Hooks {
    fn record(&self, phase: &str, request: &AuthRequest) -> AuthResult<String> {
        let mut state = self
            .0
            .lock()
            .map_err(|_| AuthError::internal("test state poisoned"))?;
        state.events.push(json!({"phase":phase,"path":request.path(),"ambient":better_auth_core::hooks::current_request_hook_context().and_then(|scope|scope.path).map(Value::String).unwrap_or_else(||json!({"$undefined":true})),"body":request.input_body()?,"query":request.input_query()?,"request":request.original_request().is_some(),"headers":request.headers}));
        Ok(state.mode.clone())
    }
    fn mode(&self, mode: &str) -> AuthResult<()> {
        let mut state = self
            .0
            .lock()
            .map_err(|_| AuthError::internal("test state poisoned"))?;
        state.mode = mode.into();
        state.events.clear();
        Ok(())
    }
    fn events(&self) -> AuthResult<Vec<Value>> {
        Ok(self
            .0
            .lock()
            .map_err(|_| AuthError::internal("test state poisoned"))?
            .events
            .clone())
    }
}
#[async_trait]
impl BeforeEndpointHook<S> for Hooks {
    async fn before(
        &self,
        request: &AuthRequest,
        _: &AuthContext<S>,
    ) -> AuthResult<Option<BeforeRequestAction>> {
        let mode = self.record("before", request)?;
        Ok(match mode.as_str() {
            "patch" => Some(BeforeRequestAction::MergeContext(EndpointInputPatch {
                body: Some(
                    json!({"email":"PATCHED@example.test","payload":{"sub":"changed"},"secret":"patched-secret"}),
                ),
                ..Default::default()
            })),
            "options" => Some(BeforeRequestAction::MergeContext(EndpointInputPatch {
                body: Some(
                    json!({"overrideOptions":{"jwt":{"issuer":"changed-issuer","audience":["one","two"],"expirationTime":9000}}}),
                ),
                ..Default::default()
            })),
            "invalid" => Some(BeforeRequestAction::MergeContext(EndpointInputPatch {
                body: Some(json!({"email":7,"payload":7,"secret":7})),
                ..Default::default()
            })),
            "stop" => Some(BeforeRequestAction::Respond(AuthResponse::json(
                200,
                &json!({"code":"stopped"}),
            )?)),
            _ => None,
        })
    }
}
#[async_trait]
impl AfterEndpointHook<S> for Hooks {
    async fn after(
        &self,
        request: &AuthRequest,
        response: &mut AuthResponse,
        _: &AuthContext<S>,
    ) -> AuthResult<()> {
        match self.record("after", request)?.as_str() {
            "replace" => response.replace_returned(AuthResponse::json(
                200,
                &json!({"code":"replaced","token":"replaced","otp":"replaced"}),
            )?),
            "after-api-error" => return Err(AuthError::bad_request("after rejection")),
            _ => (),
        }
        Ok(())
    }
}
async fn build(hooks: &Hooks) -> AuthResult<BetterAuth<S>> {
    let generator = hooks.clone();
    let mut config = AuthConfig::new("native-endpoint-fixture-secret-more-than-32");
    config.base_url = "http://native-endpoint.test".into();
    BetterAuth::stateless(config)
   .hooks(EndpointHooks{before:Some(Arc::new(hooks.clone())),after:Some(Arc::new(hooks.clone()))})
   .plugin(EmailOtpPlugin::new().callbacks(EmailOtpCallbacks::<S>::default().generate(move |_,_,endpoint|{
       let mut state=generator.0.lock().map_err(|_|AuthError::internal("test state poisoned"))?;
       state.events.push(json!({"phase":"generator","path":endpoint.path,"body":endpoint.body.json()?,"request":endpoint.request.is_some(),"ambient":better_auth_core::hooks::current_request_hook_context().map(|value|value.path)}));
       if state.mode=="ordinary" {return Err(AuthError::internal("generator failed"));}
       Ok(Some("123456".into()))
   })))
   .plugin(JwtPlugin::new()).plugin(TwoFactorPlugin::new()).build().await
}
#[tokio::test]
async fn native_facades_share_raw_hooks_projection_and_response_replacement() -> AuthResult<()> {
    let hooks = Hooks::default();
    let auth = build(&hooks).await?;
    hooks.mode("patch")?;
    assert_eq!(
        auth.email_otp()?
            .create("initial@example.test", EmailOtpType::SignIn)
            .await?,
        "123456"
    );
    let events = hooks.events()?;
    assert_eq!(
        events
            .iter()
            .map(|event| event.get("phase").and_then(Value::as_str))
            .collect::<Vec<_>>(),
        vec![Some("before"), Some("generator"), Some("after")]
    );
    assert_eq!(
        events.first().and_then(|event| event.get("ambient")),
        Some(&json!({"$undefined":true}))
    );
    assert_eq!(
        events.get(1).and_then(|event| event.get("path")),
        Some(&json!("virtual:"))
    );
    assert_eq!(
        events.get(1).and_then(|event| event.get("ambient")),
        Some(&json!("virtual:"))
    );
    assert_eq!(
        events.get(1).and_then(|event| event.get("body")),
        Some(&json!({"email":"PATCHED@example.test","type":"sign-in"}))
    );
    assert_eq!(
        events
            .get(2)
            .and_then(|event| event.pointer("/body/payload")),
        Some(&json!({"sub":"changed"}))
    );
    hooks.mode("normal")?;
    assert_eq!(
        auth.email_otp()?
            .get("patched@example.test", EmailOtpType::SignIn)
            .await?,
        Some("123456".into())
    );
    assert_eq!(
        auth.email_otp()?
            .get("initial@example.test", EmailOtpType::SignIn)
            .await?,
        None
    );
    hooks.mode("patch")?;
    let jwt = auth
        .jwt()?
        .sign(serde_json::from_value(json!({"sub":"original"}))?)
        .await?;
    hooks.mode("normal")?;
    assert_eq!(
        auth.jwt()?
            .verify(&jwt, None)
            .await?
            .and_then(|mut value| value.remove("sub")),
        Some(json!("changed"))
    );
    hooks.mode("replace")?;
    assert_eq!(
        auth.two_factor()?
            .generate_totp(Some(json!({"secret":"initial"})))
            .await?,
        "replaced"
    );
    assert_eq!(auth.jwt()?.sign(serde_json::Map::new()).await?, "replaced");
    hooks.mode("stop")?;
    assert_eq!(
        auth.two_factor()?
            .generate_totp(Some(json!({"secret":"initial"})))
            .await?,
        "stopped"
    );
    assert_eq!(hooks.events()?.len(), 1);
    Ok(())
}
#[tokio::test]
async fn validation_errors_run_after_but_ordinary_errors_do_not() -> AuthResult<()> {
    let hooks = Hooks::default();
    let auth = build(&hooks).await?;
    hooks.mode("invalid")?;
    let error = auth
        .email_otp()?
        .create("initial@example.test", EmailOtpType::SignIn)
        .await
        .err()
        .ok_or_else(|| AuthError::internal("patched invalid body must fail before generation"))?;
    assert_eq!(error.status_code()?, 400);
    assert_eq!(hooks.events()?.len(), 2);
    hooks.mode("invalid")?;
    assert_eq!(
        auth.jwt()?
            .sign(serde_json::Map::new())
            .await
            .err()
            .ok_or_else(|| AuthError::internal("invalid JWT body must fail"))?
            .status_code()?,
        400
    );
    assert_eq!(hooks.events()?.len(), 2);
    hooks.mode("ordinary")?;
    assert!(matches!(
        auth.email_otp()?
            .create("initial@example.test", EmailOtpType::SignIn)
            .await,
        Err(AuthError::Internal(_))
    ));
    assert_eq!(
        hooks
            .events()?
            .iter()
            .map(|event| event.get("phase").and_then(Value::as_str))
            .collect::<Vec<_>>(),
        vec![Some("before"), Some("generator")]
    );
    Ok(())
}
#[tokio::test]
async fn native_request_presence_and_helper_exclusion_survive_dispatch() -> AuthResult<()> {
    let hooks = Hooks::default();
    let auth = build(&hooks).await?;
    let request = AuthRequest::new(better_auth_core::HttpMethod::Post, "/outside").with_url(
        "http://localhost:3000/outside"
            .parse()
            .map_err(|e| AuthError::config(format!("fixture URL: {e}")))?,
    );
    let headers = std::collections::HashMap::from([("X-Literal".into(), "value".into())]);
    let _ = auth
        .two_factor()?
        .with_request(NativeRequest {
            request: Some(&request),
            headers: Some(&headers),
        })
        .generate_totp(Some(json!({"secret":"literal-secret"})))
        .await?;
    let events = hooks.events()?;
    assert_eq!(
        events.first().and_then(|event| event.get("request")),
        Some(&json!(true))
    );
    assert_eq!(
        events
            .first()
            .and_then(|event| event.pointer("/headers/x-literal")),
        Some(&json!("value"))
    );
    hooks.mode("normal")?;
    let _ = auth
        .jwt()?
        .create_key_pair(better_auth::plugins::JwtKeyPairConfig::new(
            better_auth::plugins::JwtAlgorithm::EdDsa,
        ))
        .await?;
    assert!(hooks.events()?.is_empty());
    Ok(())
}

#[tokio::test]
async fn shared_dispatch_data_does_not_retain_the_authentication_context() -> AuthResult<()> {
    let hooks = Hooks::default();
    let weak = Arc::downgrade(&hooks.0);
    let auth = build(&hooks).await?;
    let _ = auth
        .two_factor()?
        .generate_totp(Some(json!({"secret":"fixture"})))
        .await?;
    drop(auth);
    drop(hooks);
    assert!(weak.upgrade().is_none());
    Ok(())
}

#[tokio::test]
async fn signing_options_follow_the_validated_hook_body() -> AuthResult<()> {
    use base64::Engine;
    let hooks = Hooks::default();
    let auth = build(&hooks).await?;
    hooks.mode("options")?;
    let token = auth
        .jwt()?
        .sign(serde_json::from_value(json!({"sub":"fixture","iat":100}))?)
        .await?;
    let payload = token
        .split('.')
        .nth(1)
        .ok_or_else(|| AuthError::internal("Missing signed payload"))?;
    let value: Value = serde_json::from_slice(
        &base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(payload)
            .map_err(|error| AuthError::internal(format!("Invalid signed base64url: {error}")))?,
    )?;
    assert_eq!(value.get("iss"), Some(&json!("changed-issuer")));
    assert_eq!(value.get("aud"), Some(&json!(["one", "two"])));
    assert_eq!(value.get("exp"), Some(&json!(9000)));
    Ok(())
}

#[tokio::test]
async fn update_user_preserves_native_builtin_error_declarations() -> AuthResult<()> {
    use better_auth::server_api::EndpointInput;
    use better_auth_core::{ApiErrorClass, CreateSession, CreateUser, HttpMethod};
    use chrono::Utc;
    use std::collections::HashMap;

    let hooks = Hooks::default();
    let auth = build(&hooks).await?;
    let user = auth
        .store()
        .create_user(
            CreateUser::new()
                .with_name("Owner")
                .with_email("owner@status.test")
                .with_email_verified(true),
        )
        .await?;
    let session = auth
        .store()
        .create_session(CreateSession {
            inherited_fields: Default::default(),
            additional_fields: Default::default(),
            user_id: user.id.clone(),
            expires_at: (Utc::now() + auth.config().session.expires_in()).into(),
            ip_address: None,
            user_agent: None,
            impersonated_by: None,
            active_organization_id: None,
        })
        .await?;
    let headers = HashMap::from([(
        "cookie".to_owned(),
        format!(
            "better-auth.session_token={}",
            better_auth_core::utils::cookie_utils::sign_cookie_value(
                session.token.typed()?,
                &auth.config().secret,
            )
        ),
    )]);
    let stored = serde_json::to_value(&user)?;
    let stored_session = serde_json::to_value(&session)?;
    for (authenticated, body, status, code, expected) in [
        (
            false,
            json!({}),
            "UNAUTHORIZED",
            401,
            json!({"message":"Unauthorized","code":"UNAUTHORIZED"}),
        ),
        (
            true,
            json!({"email":"changed@status.test"}),
            "BAD_REQUEST",
            400,
            json!({"message":"Email can not be updated","code":"EMAIL_CAN_NOT_BE_UPDATED"}),
        ),
        (
            true,
            json!({}),
            "BAD_REQUEST",
            400,
            json!({"message":"No fields to update"}),
        ),
    ] {
        let error = auth
            .call_endpoint(
                HttpMethod::Post,
                "/update-user",
                EndpointInput {
                    body: Some(body),
                    headers: Some(if authenticated {
                        headers.clone()
                    } else {
                        HashMap::new()
                    }),
                    ..Default::default()
                },
            )
            .await
            .err()
            .ok_or_else(|| AuthError::internal("Invalid user update must fail"))?;
        assert!(error.is_api_error_instance(ApiErrorClass::BetterAuth));
        assert_eq!(error.status_value()?, status.into());
        assert_eq!(error.status_code()?, code);
        assert_eq!(error.body_value()?.json()?, Some(expected.clone()));
        let response = error
            .to_auth_response()
            .expect("fixture response succeeds")
            .into_http_response()?;
        assert_eq!(response.status, code);
        assert_eq!(
            response.body.bytes()?.as_ref(),
            serde_json::to_vec(&expected)?
        );
        assert_eq!(
            serde_json::to_value(auth.store().get_user_by_id(user.id.typed()?).await?)?,
            stored
        );
        assert_eq!(
            serde_json::to_value(auth.store().get_session(session.token.typed()?).await?)?,
            stored_session
        );
    }
    Ok(())
}
