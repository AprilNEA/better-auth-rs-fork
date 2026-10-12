use async_trait::async_trait;
use better_auth::{BetterAuth, plugins::OpenApiPlugin};
use better_auth_core::{
    AuthConfig, AuthContext, AuthError, AuthPlugin, AuthRequest, AuthResponse, AuthResult,
    AuthRoute, AuthSchema, RateLimitConfig,
    user_fields::{UserConfig, UserFieldConfig},
};
use serde_json::{Value, json};

struct ExplicitModels;

#[async_trait]
impl<S: AuthSchema> AuthPlugin<S> for ExplicitModels {
    fn name(&self) -> &'static str {
        "ordinary-model-key-order"
    }

    fn routes(&self) -> Vec<AuthRoute> {
        Vec::new()
    }

    fn schema(
        &self,
        context: &mut better_auth_core::plugin_runtime::ModelFields,
    ) -> AuthResult<()> {
        for name in ["tail", "10", "2", "01", "4294967294", "4294967295"] {
            let fields = UserConfig {
                additional_fields: Some(
                    [(
                        "label".into(),
                        UserFieldConfig {
                            required: Some(true),
                            default_value: Some(name.into()),
                            ..Default::default()
                        },
                    )]
                    .into(),
                ),
            };
            context.register_custom_model(name, None, fields)?;
        }
        Ok(())
    }

    async fn on_request(
        &self,
        _: &AuthRequest,
        _: &AuthContext<S>,
    ) -> AuthResult<Option<AuthResponse>> {
        Ok(None)
    }
}

#[tokio::test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "The test propagates setup errors and compares complete captured components and the native model-key array."
)]
async fn native_components_preserve_javascript_model_key_enumeration()
-> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let expected: Value =
        serde_json::from_str(include_str!("fixtures/openapi-model-key-order-1.7.6.json"))?;
    let mut config =
        AuthConfig::new("ordinary-openapi-model-key-order-secret-at-least-32-characters")
            .base_url("http://openapi-model-key-order.test");
    {
        let better_auth_core::LoggerSource::Config(logger_options) = &mut config.logger else {
            #[allow(
                clippy::panic,
                clippy::panic_in_result_fn,
                reason = "The fixture modifies its existing authored logger options."
            )]
            {
                panic!("fixture requires authored logger options");
            }
        };
        logger_options.disabled = Some(true);
    }
    config.telemetry.enabled = false;
    let auth = BetterAuth::stateless(config)
        .rate_limit(RateLimitConfig::new().enabled(false))
        .plugin(ExplicitModels)
        .plugin(OpenApiPlugin::new())
        .build()
        .await?;
    let document = auth.openapi_spec()?.to_value()?;
    let components = document
        .get("components")
        .ok_or_else(|| AuthError::internal("Expected the complete generated components"))?;
    let schemas = components
        .get("schemas")
        .and_then(Value::as_object)
        .ok_or_else(|| AuthError::internal("Expected the generated component model map"))?;
    let model_keys: Vec<_> = schemas.keys().collect();
    assert_eq!(
        json!({ "version": "1.7.6", "components": components, "modelKeys": model_keys }),
        expected
    );
    Ok(())
}
