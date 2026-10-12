//! Rust business helpers retain instance logging without acquiring the auth.api hook pipeline.

use super::*;
use better_auth::{
    plugins::api_key::{ApiKeyConfig, ApiKeyGenerator, ApiKeyPlugin},
    server_api::CreateKeyOptions,
};
use better_auth_core::{CreateUser, endpoint_dispatch::EndpointDispatcher};
use tracing::instrument::WithSubscriber;

struct Generator {
    failure: Option<FieldValue>,
}

#[async_trait]
impl ApiKeyGenerator for Generator {
    async fn generate(&self, _: usize, _: Option<&str>) -> AuthResult<String> {
        logger::current().error("generator:enter", &[])?;
        tokio::task::yield_now().await;
        logger::current().error("generator:resumed", &[])?;
        match &self.failure {
            Some(cause) => Err(AuthError::from_thrown(cause.clone())),
            None => Ok("facade-controlled-token".into()),
        }
    }
}

async fn create(
    auth: &BetterAuth<S>,
    user_id: &str,
    failure: Option<&FieldValue>,
    observations: &Observations,
    store: &EphemeralStore,
) -> AuthResult<()> {
    let result = auth
        .api_keys()?
        .create(
            user_id,
            CreateKeyOptions {
                rate_limit_enabled: Some(false),
                ..Default::default()
            },
        )
        .await;
    observations.phase("B:result")?;
    match (failure, result) {
        (Some(cause), Err(error)) => {
            assert!(
                error
                    .raw_value()
                    .is_some_and(|value| value.strict_equals(cause))
            );
            assert!(store.storage_rows(EntityRole::ApiKey)?.is_empty());
        }
        (None, Ok(issued)) => {
            assert_eq!(issued.key, "facade-controlled-token");
            assert_eq!(issued.api_key.reference_id, user_id);
            let rows = store.storage_rows(EntityRole::ApiKey)?;
            let [row] = rows.as_slice() else {
                return Err(AuthError::internal(
                    "Successful facade issuance must persist exactly one key",
                ));
            };
            assert!(
                row.get("id")
                    .is_some_and(|value| value.strict_equals(&issued.api_key.id.field_value()))
            );
            assert_eq!(row.get("key"), Some(&"facade-controlled-token".into()));
        }
        (None, Err(error)) => return Err(error),
        (Some(_), Ok(_)) => {
            return Err(AuthError::internal(
                "Generator failure must escape the typed facade",
            ));
        }
    }
    Ok(())
}

#[tokio::test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "The contract must assert logger ownership, complete event order, and persistence while setup errors propagate"
)]
async fn typed_api_key_facade_retains_its_logger_across_await_and_restores_the_caller()
-> AuthResult<()> {
    for nested in [false, true] {
        for fails in [false, true] {
            let observations = Arc::new(Observations::default());
            let cause: FieldValue = FieldMap::from([
                ("name".into(), "Error".into()),
                ("message".into(), "controlled generator failure".into()),
            ])
            .into();
            let failure = fails.then_some(&cause);
            let mut b_config = config(ORIGIN_B);
            {
                let better_auth_core::LoggerSource::Config(logger_options) = &mut b_config.logger
                else {
                    #[allow(
                        clippy::panic,
                        clippy::panic_in_result_fn,
                        reason = "The fixture modifies its existing authored logger options."
                    )]
                    panic!("fixture requires authored logger options");
                };
                logger_options.level = Some(LogLevel::Error);
                logger_options.log = Some(observations.sink("B")?);
            }
            let (b_builder, b_store) = builder(b_config, &["apikey"])?;
            let b = b_builder
                .plugin(ApiKeyPlugin::with_config(ApiKeyConfig {
                    disable_key_hashing: true,
                    custom_key_generator: Some(Arc::new(Generator {
                        failure: failure.cloned(),
                    })),
                    ..Default::default()
                }))
                .build()
                .await?;
            let user = b
                .store()
                .create_user(
                    CreateUser::new()
                        .with_email("scope@example.test")
                        .with_name("Scope"),
                )
                .await?;
            let user_id = user.id.typed()?.clone();
            let stored_before = snapshot(&b_store)?;
            let mut a_config = config(ORIGIN_A);
            {
                let better_auth_core::LoggerSource::Config(logger_options) = &mut a_config.logger
                else {
                    #[allow(
                        clippy::panic,
                        clippy::panic_in_result_fn,
                        reason = "The fixture modifies its existing authored logger options."
                    )]
                    panic!("fixture requires authored logger options");
                };
                logger_options.level = Some(LogLevel::Error);
                logger_options.log = Some(observations.sink("A")?);
            }
            let (a_builder, a_store) = builder(a_config, &[])?;
            let a = a_builder.build().await?;
            lock(&observations.events)?.clear();
            async {
                if nested {
                    let route = AuthRoute::get("/facade", "facade");
                    let dispatcher = EndpointDispatcher::<S>::new(
                        Arc::new(Vec::new()),
                        Default::default(),
                        [route.clone()],
                    );
                    let response = dispatcher
                        .native(
                            request(ORIGIN_A, "/facade")?,
                            route,
                            a.context(),
                            |_, context| {
                                let (b, user_id, observations, b_store) =
                                    (&b, &user_id, observations.as_ref(), b_store.as_ref());
                                async move {
                                    assert!(std::ptr::eq(
                                        context.as_ref(),
                                        context
                                            .current_request_context()
                                            .ok_or_else(|| AuthError::internal(
                                                "Native endpoint context must be active"
                                            ))?
                                            .as_ref()
                                    ));
                                    observations.phase("A:enter")?;
                                    create(b, user_id, failure, observations, b_store).await?;
                                    observations.phase("A:restored")?;
                                    Ok(AuthResponse::new(204))
                                }
                            },
                        )
                        .await?;
                    assert_eq!(response.status, 204);
                } else {
                    create(&b, &user_id, failure, &observations, &b_store).await?;
                }
                Ok::<_, AuthError>(())
            }
            .with_subscriber(capture::DefaultLogger(observations.clone()))
            .await?;
            let mut expected = if nested {
                vec![Event::Phase("A:enter", "A")]
            } else {
                Vec::new()
            };
            for message in ["generator:enter", "generator:resumed"] {
                expected.push(Event::Log {
                    sink: "B",
                    scope: "B",
                    level: LogLevel::Error,
                    message: message.into(),
                    arguments: Vec::new(),
                });
            }
            expected.push(Event::Phase("B:result", if nested { "A" } else { "none" }));
            if nested {
                expected.push(Event::Phase("A:restored", "A"));
            }
            assert_eq!(*lock(&observations.events)?, expected);
            assert_eq!(observations.owner(), "none");
            assert!(a.context().current_request_context().is_none());
            assert!(b.context().current_request_context().is_none());
            assert_eq!(snapshot(&b_store)?, stored_before);
            assert_eq!(
                snapshot(&a_store)?,
                json!({"user": [], "session": [], "account": [], "verification": []})
            );
        }
    }
    Ok(())
}
