use async_trait::async_trait;
use better_auth::plugins::{AdminPlugin, AnonymousPlugin, PhoneNumberPlugin, TwoFactorPlugin};
use better_auth::{AuthBuilder, AuthConfig, BetterAuth};
use better_auth_core::{
    ApiErrorClass, AuthContext, AuthError, AuthPlugin, AuthRequest, AuthResponse, AuthResult,
    AuthRoute, AuthSchema, FieldMap, FieldValue,
    store::{EphemeralStore, StatelessSchema},
    user_fields::{
        FieldTransforms, FieldValidators, UserConfig, UserFieldConfig, UserFieldTransform,
    },
};
use serde_json::{Map, Value, json};
use std::sync::{Arc, Mutex};

const FIELDS: [&str; 7] = [
    "role",
    "banned",
    "banReason",
    "banExpires",
    "phoneNumberVerified",
    "isAnonymous",
    "twoFactorEnabled",
];
type Trace = Arc<Mutex<Vec<String>>>;

struct Policies(&'static str, UserConfig);

#[async_trait]
impl<S: AuthSchema> AuthPlugin<S> for Policies {
    fn name(&self) -> &'static str {
        self.0
    }
    fn routes(&self) -> Vec<AuthRoute> {
        Vec::new()
    }
    fn schema(
        &self,
        context: &mut better_auth_core::plugin_runtime::ModelFields,
    ) -> AuthResult<()> {
        context.register_user_fields(self.1.clone());
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

fn record(trace: &Trace, event: String) -> AuthResult<()> {
    trace
        .lock()
        .map_err(|_| AuthError::internal("User policy trace lock poisoned"))?
        .push(event);
    Ok(())
}

fn take_trace(trace: &Trace) -> AuthResult<Vec<String>> {
    Ok(std::mem::take(&mut *trace.lock().map_err(|_| {
        AuthError::internal("User policy trace lock poisoned")
    })?))
}

fn policies(
    label: &'static str,
    trace: &Trace,
    reject: Option<&'static str>,
    protected: bool,
) -> UserConfig {
    UserConfig {
        additional_fields: Some(
            FIELDS
                .into_iter()
                .map(|name| {
                    let input_trace = trace.clone();
                    let validate_trace = trace.clone();
                    (
                        name.into(),
                        UserFieldConfig {
                            input: Some(!protected),
                            default_value: protected.then(|| "replacement-default".into()),
                            validator: (name == "role").then(|| FieldValidators {
                                input: Some(Arc::new(move |_| {
                                    record(&validate_trace, format!("{label}:validate:{name}"))?;
                                    if reject == Some(name) {
                                        return Err(AuthError::bad_request("validator denied"));
                                    }
                                    Ok(format!("{label}:{name}").into())
                                })),
                                ..Default::default()
                            }),
                            transform: Some(FieldTransforms {
                                input: Some(UserFieldTransform::new(move |_| {
                                    record(&input_trace, format!("{label}:transform:{name}"))?;
                                    if reject == Some(name) {
                                        return Err(AuthError::bad_request("transform denied"));
                                    }
                                    Ok(format!("{label}:{name}").into())
                                })),
                                ..Default::default()
                            }),
                            ..Default::default()
                        },
                    )
                })
                .collect(),
        ),
    }
}

fn builder(config: AuthConfig) -> AuthBuilder<StatelessSchema> {
    BetterAuth::new(config).store(EphemeralStore::default())
}

fn native(builder: AuthBuilder<StatelessSchema>) -> AuthBuilder<StatelessSchema> {
    builder
        .plugin(AdminPlugin::new())
        .plugin(PhoneNumberPlugin::new())
        .plugin(AnonymousPlugin::new())
        .plugin(TwoFactorPlugin::new())
}

fn config() -> AuthConfig {
    AuthConfig::new("user-input-policy-contract-secret-at-least-32-characters")
        .base_url("http://user-policy.test")
}

fn defaults() -> FieldMap {
    ["banned", "isAnonymous", "twoFactorEnabled"]
        .into_iter()
        .map(|name| (name.into(), false.into()))
        .collect()
}

#[expect(
    clippy::panic_in_result_fn,
    reason = "Schema errors must preserve both API classes, named status, and ordered bodies"
)]
fn schema_failure(error: &AuthError) -> AuthResult<()> {
    assert!(error.is_api_error_instance(ApiErrorClass::BetterAuth));
    assert!(error.is_api_error_instance(ApiErrorClass::BetterCall));
    assert_eq!(error.status_value()?, FieldValue::from("BAD_REQUEST"));
    assert_eq!(error.status_code()?, 400);
    assert_eq!(
        error
            .body_value()?
            .enumerable_fields()?
            .keys()
            .collect::<Vec<_>>(),
        ["message", "code"]
    );
    Ok(())
}

#[expect(
    clippy::panic_in_result_fn,
    reason = "Protected-field failures retain their typed code and complete message"
)]
fn denied(result: AuthResult<FieldMap>, name: &str) -> AuthResult<()> {
    assert!(
        matches!(result, Err(AuthError::FieldInput { code: "FIELD_NOT_ALLOWED", ref message })
        if message == &format!("{name} is not allowed to be set")),
        "{result:?}"
    );
    let error = result
        .err()
        .ok_or_else(|| AuthError::internal("Protected field was accepted"))?;
    schema_failure(&error)
}

#[tokio::test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "The contract asserts protected-field behavior while propagating setup and field-access errors"
)]
async fn native_user_input_declarations_preserve_default_protection() -> AuthResult<()> {
    let auth = native(builder(config())).build().await?;
    let context = auth.context();
    assert_eq!(context.parse_user_input(&Map::new(), true)?, defaults());
    assert_eq!(
        context.parse_user_input(&Map::new(), false)?,
        FieldMap::new()
    );
    for name in FIELDS {
        let input = [(name.into(), json!(true))].into_iter().collect();
        if ["banned", "isAnonymous", "twoFactorEnabled"].contains(&name) {
            assert_eq!(context.parse_user_input(&input, true)?, defaults());
        } else {
            denied(context.parse_user_input(&input, true), name)?;
        }
        denied(context.parse_user_input(&input, false), name)?;
        for value in [Value::Null, json!(false), json!(0), json!("")] {
            let input = [(name.into(), value)].into_iter().collect();
            assert_eq!(context.parse_user_input(&input, true)?, defaults());
            assert_eq!(context.parse_user_input(&input, false)?, FieldMap::new());
        }
    }
    Ok(())
}

#[tokio::test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "The contract asserts declaration precedence and callback order while propagating setup errors"
)]
async fn user_input_replacements_follow_real_plugin_order_and_stop_at_callback_errors()
-> AuthResult<()> {
    for late in [false, true] {
        for reject in [None, Some("role"), Some("banReason")] {
            let trace = Trace::default();
            let mut configuration = config();
            configuration.user = policies("application", &trace, None, false);
            let mut builder = native(builder(configuration).plugin(Policies(
                "early-policy",
                policies("early", &trace, None, false),
            )));
            if late {
                builder = builder.plugin(Policies(
                    "late-policy",
                    policies("late", &trace, reject, false),
                ));
            }
            let auth = builder.build().await?;
            let context = auth.context();
            assert_eq!(
                context.adapter_user_fields().fields()["role"].input,
                Some(true)
            );
            assert!(take_trace(&trace)?.is_empty());
            let input = FIELDS
                .into_iter()
                .map(|name| (name.into(), json!(true)))
                .collect();
            for create in [true, false] {
                let parsed = context.parse_user_input(&input, create);
                if !late {
                    denied(parsed, "role")?;
                    assert!(take_trace(&trace)?.is_empty());
                    continue;
                }
                match reject {
                    Some("role") => {
                        assert!(
                            matches!(parsed, Err(AuthError::FieldInput { code: "VALIDATION_ERROR", ref message }) if message == "validator denied")
                        );
                        let error = parsed.err().ok_or_else(|| {
                            AuthError::internal("Validator rejection was ignored")
                        })?;
                        schema_failure(&error)?;
                        assert_eq!(take_trace(&trace)?, ["late:validate:role"]);
                    }
                    Some("banReason") => {
                        assert!(
                            matches!(parsed, Err(AuthError::BadRequest(ref message)) if message == "transform denied")
                        );
                        assert_eq!(
                            take_trace(&trace)?,
                            [
                                "late:validate:role",
                                "late:transform:banned",
                                "late:transform:banReason"
                            ]
                        );
                    }
                    _ => {
                        let expected: FieldMap = FIELDS
                            .into_iter()
                            .map(|name| (name.into(), format!("late:{name}").into()))
                            .collect();
                        let parsed = parsed?;
                        assert_eq!(parsed, expected);
                        assert_eq!(
                            parsed.keys().map(String::as_str).collect::<Vec<_>>(),
                            FIELDS
                        );
                        assert_eq!(
                            take_trace(&trace)?,
                            FIELDS
                                .into_iter()
                                .map(|name| format!(
                                    "late:{}:{name}",
                                    if name == "role" {
                                        "validate"
                                    } else {
                                        "transform"
                                    }
                                ))
                                .collect::<Vec<_>>()
                        );
                    }
                }
            }
            assert_eq!(
                context.parse_user_input(&Map::new(), true)?,
                if late { FieldMap::new() } else { defaults() }
            );
            assert!(take_trace(&trace)?.is_empty());
        }
    }
    Ok(())
}

#[tokio::test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "The contract asserts replacement defaults and zero callbacks while propagating setup errors"
)]
async fn protected_replacement_defaults_override_native_guards_without_callbacks() -> AuthResult<()>
{
    let trace = Trace::default();
    let auth = native(builder(config()))
        .plugin(Policies(
            "protected-policy",
            policies("protected", &trace, Some("role"), true),
        ))
        .build()
        .await?;
    let context = auth.context();
    let input = FIELDS
        .into_iter()
        .map(|name| (name.into(), json!(true)))
        .collect();
    let expected: FieldMap = FIELDS
        .into_iter()
        .map(|name| (name.into(), "replacement-default".into()))
        .collect();
    assert_eq!(context.parse_user_input(&input, true)?, expected);
    assert_eq!(context.parse_user_input(&Map::new(), true)?, expected);
    denied(context.parse_user_input(&input, false), "role")?;
    assert!(take_trace(&trace)?.is_empty());
    Ok(())
}

#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "Required fields must retain the same named schema error as protected and invalid fields"
)]
fn missing_user_fields_retain_named_schema_errors() -> AuthResult<()> {
    let fields = UserConfig {
        additional_fields: Some(
            [(
                "required".into(),
                UserFieldConfig {
                    required: Some(true),
                    ..Default::default()
                },
            )]
            .into(),
        ),
    };
    let error = fields
        .parse_input(&FieldMap::new(), true)
        .err()
        .ok_or_else(|| AuthError::internal("Required field was accepted"))?;
    assert!(
        matches!(error, AuthError::FieldInput { code: "MISSING_FIELD", ref message } if message == "required is required")
    );
    schema_failure(&error)?;
    assert!(fields.parse_input(&FieldMap::new(), false)?.is_empty());
    Ok(())
}

#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "Field callbacks must preserve original error identity and stop later field evaluation"
)]
fn user_input_factory_and_transform_propagate_original_failures() -> AuthResult<()> {
    for factory in [false, true] {
        let trace = Trace::default();
        let failure = AuthError::from_code("CONFLICT", "VALIDATION_ERROR", "callback rejected");
        let failure = failure
            .raw_value()
            .cloned()
            .ok_or_else(|| AuthError::internal("Expected native callback failure"))?;
        let rejected = {
            let failure = failure.clone();
            let trace = trace.clone();
            move || {
                record(&trace, if factory { "factory" } else { "transform" }.into())?;
                Err(AuthError::from_thrown(failure.clone()))
            }
        };
        let field = if factory {
            UserFieldConfig {
                default_value_fn: Some(Arc::new(rejected)),
                ..Default::default()
            }
        } else {
            UserFieldConfig {
                transform: Some(FieldTransforms {
                    input: Some(UserFieldTransform::new(move |_| rejected())),
                    ..Default::default()
                }),
                ..Default::default()
            }
        };
        let fields = UserConfig {
            additional_fields: Some(
                [
                    ("value".into(), field),
                    (
                        "later".into(),
                        UserFieldConfig {
                            default_value_fn: Some(Arc::new({
                                let trace = trace.clone();
                                move || {
                                    record(&trace, "later".into())?;
                                    Ok("later".into())
                                }
                            })),
                            ..Default::default()
                        },
                    ),
                ]
                .into(),
            ),
        };
        let input = if factory {
            FieldMap::new()
        } else {
            FieldMap::from([("value".into(), true.into())])
        };
        let error = fields
            .parse_input(&input, true)
            .err()
            .ok_or_else(|| AuthError::internal("Field callback failure was ignored"))?;
        assert!(
            error
                .raw_value()
                .is_some_and(|value| value.strict_equals(&failure))
        );
        assert_eq!(error.status_value()?, FieldValue::from("CONFLICT"));
        assert!(error.is_api_error_instance(ApiErrorClass::BetterAuth));
        assert_eq!(
            take_trace(&trace)?,
            [if factory { "factory" } else { "transform" }]
        );
        let error = AuthError::from_returned_response(error.to_auth_response())?;
        assert!(
            error
                .raw_value()
                .is_some_and(|value| value.strict_equals(&failure))
        );
    }
    Ok(())
}
