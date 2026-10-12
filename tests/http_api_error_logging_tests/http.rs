use super::*;
use better_auth_core::{ApiErrorInit, middleware::Middleware};
use tracing::instrument::WithSubscriber;

struct Failure {
    cause: FieldValue,
    observations: Arc<Observations>,
}

#[async_trait]
impl Middleware for Failure {
    fn name(&self) -> &'static str {
        "http-api-error-b"
    }

    async fn before_request(&self, _: &AuthRequest) -> AuthResult<Option<AuthResponse>> {
        self.observations.phase("B:middleware")?;
        Err(AuthError::from_thrown(self.cause.clone()))
    }
}

struct Unreachable;

#[async_trait]
impl AuthPlugin<S> for Unreachable {
    fn name(&self) -> &'static str {
        "http-api-error-b"
    }

    fn routes(&self) -> Vec<AuthRoute> {
        vec![AuthRoute::get("/failure", "failure")]
    }

    async fn on_request(
        &self,
        _: &AuthRequest,
        _: &AuthContext<S>,
    ) -> AuthResult<Option<AuthResponse>> {
        Err(AuthError::internal(
            "The failed middleware must prevent the B endpoint handler",
        ))
    }
}

struct Parent {
    child: Arc<BetterAuth<S>>,
    observations: Arc<Observations>,
}

#[async_trait]
impl AuthPlugin<S> for Parent {
    fn name(&self) -> &'static str {
        "http-api-error-a"
    }

    fn routes(&self) -> Vec<AuthRoute> {
        vec![AuthRoute::get("/nested", "nested")]
    }

    async fn on_request(
        &self,
        _: &AuthRequest,
        context: &AuthContext<S>,
    ) -> AuthResult<Option<AuthResponse>> {
        let parent = context
            .current_request_context()
            .ok_or_else(|| AuthError::internal("Parent endpoint context must be active"))?;
        assert!(std::ptr::eq(context, parent.as_ref()));
        self.observations.phase("A:enter")?;
        let response = self
            .child
            .handle_request(request(ORIGIN_B, "/failure")?)
            .await?;
        assert!(Arc::ptr_eq(
            &parent,
            &context
                .current_request_context()
                .ok_or_else(|| AuthError::internal("Parent endpoint context must be restored"))?,
        ));
        assert!(self.child.context().current_request_context().is_none());
        self.observations.phase("A:restored")?;
        *lock(&self.observations.inner_response)? = Some(response_snapshot(&response)?);
        Ok(Some(response))
    }
}

fn error_snapshot(cause: &FieldValue) -> AuthResult<Vec<(String, bool, FieldValue)>> {
    let object = cause
        .as_object()
        .ok_or_else(|| AuthError::internal("APIError must be an object"))?;
    object
        .own_keys()?
        .into_iter()
        .map(|name| {
            let descriptor = object.own_property_descriptor(&name)?.ok_or_else(|| {
                AuthError::internal("APIError property must retain its descriptor")
            })?;
            let value = object
                .get(&name)?
                .ok_or_else(|| AuthError::internal("APIError property must remain present"))?;
            Ok((name, descriptor.enumerable, value))
        })
        .collect()
}

#[tokio::test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "The paired contract must assert complete responses, logger events, and original error identity while setup errors propagate"
)]
async fn http_api_errors_keep_instance_and_exported_logger_scopes_distinct() -> AuthResult<()> {
    for nested in [false, true] {
        for status in ["FORBIDDEN", "INTERNAL_SERVER_ERROR"] {
            for level in [
                None,
                Some(LogLevel::Error),
                Some(LogLevel::Warn),
                Some(LogLevel::Debug),
                Some(LogLevel::Info),
            ] {
                for disabled in [false, true] {
                    let observations = Arc::new(Observations::default());
                    let body: FieldValue = FieldMap::from([
                        ("message".into(), MESSAGE.into()),
                        ("code".into(), "SCOPED_FAILURE".into()),
                        (
                            "details".into(),
                            FieldMap::from([
                                ("retry".into(), false.into()),
                                ("owner".into(), "B".into()),
                            ])
                            .into(),
                        ),
                    ])
                    .into();
                    let headers: FieldValue =
                        FieldMap::from([("x-api-error".into(), "B".into())]).into();
                    let error = AuthError::try_api_error(ApiErrorInit {
                        status: status.into(),
                        body: body.clone(),
                        headers: headers.clone(),
                        ..Default::default()
                    })?;
                    let cause = error.raw_value().cloned().ok_or_else(|| {
                        AuthError::internal("APIError must retain its native value")
                    })?;
                    let before_error = error_snapshot(&cause)?;
                    let mut b_config = config(ORIGIN_B);
                    b_config.logger.level = level;
                    b_config.logger.disabled = Some(disabled);
                    b_config.logger.log = Some(observations.sink("B")?);
                    let (b_builder, b_store) = builder(b_config, &[])?;
                    let b = Arc::new(
                        b_builder
                            .middleware(Failure {
                                cause: cause.clone(),
                                observations: observations.clone(),
                            })
                            .plugin(Unreachable)
                            .build()
                            .await?,
                    );
                    let mut a_config = config(ORIGIN_A);
                    a_config.logger.level = Some(LogLevel::Error);
                    a_config.logger.log = Some(observations.sink("A")?);
                    let (a_builder, a_store) = builder(a_config, &[])?;
                    let a = a_builder
                        .plugin(Parent {
                            child: b.clone(),
                            observations: observations.clone(),
                        })
                        .build()
                        .await?;
                    let roots = [
                        (
                            a.context().base_url(),
                            a.context().config.base_url.as_static().map(str::to_owned),
                        ),
                        (
                            b.context().base_url(),
                            b.context().config.base_url.as_static().map(str::to_owned),
                        ),
                    ];
                    lock(&observations.events)?.clear();
                    let before = chrono::Utc::now();
                    let response = async {
                        if nested {
                            a.handle_request(request(ORIGIN_A, "/nested")?).await
                        } else {
                            b.handle_request(request(ORIGIN_B, "/failure")?).await
                        }
                    }
                    .with_subscriber(capture::DefaultLogger(observations.clone()))
                    .await?;
                    let after = chrono::Utc::now();
                    let actual_response = response_snapshot(&response)?;
                    lock(&observations.events)?.push(Event::Response(actual_response.clone()));
                    let expected_response = json!({
                        "status": if status == "FORBIDDEN" { 403 } else { 500 },
                        "statusText": status,
                        "headers": [["content-type", "application/json"], ["x-api-error", "B"]],
                        "cookies": [],
                        "body": body.stringify()?.ok_or_else(|| AuthError::internal("Fixture body must serialize"))?,
                    });
                    assert_eq!(actual_response, expected_response);
                    assert_eq!(
                        *lock(&observations.inner_response)?,
                        nested.then_some(expected_response.clone())
                    );
                    let events = lock(&observations.events)?.clone();
                    let mut expected = if nested {
                        vec![Event::Phase("A:enter", "A")]
                    } else {
                        Vec::new()
                    };
                    let scope = if nested { "A" } else { "none" };
                    expected.push(Event::Phase("B:middleware", scope));
                    if !disabled && status == "INTERNAL_SERVER_ERROR" {
                        expected.push(Event::Log {
                            sink: "B",
                            scope,
                            level: LogLevel::Error,
                            message: status.into(),
                            arguments: vec![cause.clone()],
                        });
                    }
                    if !disabled
                        && matches!(
                            level,
                            Some(LogLevel::Error | LogLevel::Warn | LogLevel::Debug)
                        )
                    {
                        if nested {
                            expected.push(Event::Log {
                                sink: "A",
                                scope: "A",
                                level: LogLevel::Error,
                                message: MESSAGE.into(),
                                arguments: Vec::new(),
                            });
                        } else {
                            expected.push(capture::default_event(&events, before, after)?);
                        }
                    }
                    if nested {
                        expected.push(Event::Phase("A:restored", "A"));
                    }
                    expected.push(Event::Response(expected_response));
                    assert_eq!(
                        events, expected,
                        "nested={nested} status={status} level={level:?} disabled={disabled}"
                    );
                    for event in &events {
                        if let Event::Log {
                            sink: "B",
                            arguments,
                            ..
                        } = event
                        {
                            assert!(
                                matches!(arguments.as_slice(), [value] if value.strict_equals(&cause))
                            );
                        }
                    }
                    assert_eq!(error_snapshot(&cause)?, before_error);
                    assert!(cause.model_property("body")?.strict_equals(&body));
                    assert!(cause.model_property("headers")?.strict_equals(&headers));
                    assert_eq!(
                        [
                            (
                                a.context().base_url(),
                                a.context().config.base_url.as_static().map(str::to_owned)
                            ),
                            (
                                b.context().base_url(),
                                b.context().config.base_url.as_static().map(str::to_owned)
                            ),
                        ],
                        roots
                    );
                    assert!(a.context().current_request_context().is_none());
                    assert!(b.context().current_request_context().is_none());
                    assert_eq!(observations.owner(), "none");
                    let empty =
                        json!({"user": [], "session": [], "account": [], "verification": []});
                    assert_eq!(snapshot(&a_store)?, empty);
                    assert_eq!(snapshot(&b_store)?, empty);
                }
            }
        }
    }
    Ok(())
}
