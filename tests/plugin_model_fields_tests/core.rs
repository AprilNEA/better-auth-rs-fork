use super::*;
use better_auth_core::plugin_runtime::ModelFields;

struct LegacyFields(&'static str, UserConfig, Arc<Mutex<Vec<&'static str>>>);

#[async_trait]
impl<S: AuthSchema> AuthPlugin<S> for LegacyFields {
    fn name(&self) -> &'static str {
        self.0
    }
    fn routes(&self) -> Vec<AuthRoute> {
        Vec::new()
    }
    fn schema(&self, fields: &mut better_auth_core::plugin_runtime::ModelFields) -> AuthResult<()> {
        fields.register_user_fields(self.1.clone());
        Ok(())
    }
    async fn on_init(&self, _context: &mut AuthInitContext<S>) -> AuthResult<()> {
        trace_lock(&self.2)?.push(self.0);
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

async fn legacy_contract<S: AuthSchema>(raw: Arc<dyn AuthStore<S>>) -> AuthResult<()> {
    let events = Arc::new(Mutex::new(Vec::new()));
    let initializations = Arc::new(Mutex::new(Vec::new()));
    let policy = |label: &'static str| {
        let events = events.clone();
        fields(
            "name",
            UserFieldConfig {
                transform: Some(FieldTransforms {
                    input: Some(UserFieldTransform::new(move |value| {
                        trace_lock(&events)?.push(label);
                        Ok(match value {
                            FieldValue::Undefined => FieldValue::Undefined,
                            value => format!(
                                "{label}:{}",
                                required(value.as_str(), "Expected a string field callback value")?
                            )
                            .into(),
                        })
                    })),
                    ..Default::default()
                }),
                ..Default::default()
            },
        )
    };
    let auth = BetterAuth::new(config())
        .store_arc(raw)
        .plugin(LegacyFields(
            "first",
            policy("first"),
            initializations.clone(),
        ))
        .plugin(LegacyFields(
            "second",
            policy("second"),
            initializations.clone(),
        ))
        .build()
        .await?;
    let user = auth
        .store()
        .create_user(
            CreateUser::new()
                .with_name("Name")
                .with_email("legacy@fields.test"),
        )
        .await?;
    assert_eq!(user.name.json()?, Some(json!("second:Name")));
    assert_eq!(*trace_lock(&events)?, ["second"]);
    assert_eq!(*trace_lock(&initializations)?, ["first", "second"]);
    Ok(())
}

#[tokio::test]
async fn memory_legacy_registration_replaces_once_in_plugin_order() -> AuthResult<()> {
    legacy_contract(memory()).await
}
#[tokio::test]
async fn sqlite_legacy_registration_replaces_once_in_plugin_order() -> AuthResult<()> {
    legacy_contract(sqlite().await?).await
}

struct LifecycleFields {
    name: &'static str,
    events: Arc<Mutex<Vec<String>>>,
    declarations: Arc<Mutex<Option<ModelFields>>>,
    fail: bool,
}

#[async_trait]
impl AuthPlugin<StatelessSchema> for LifecycleFields {
    fn name(&self) -> &'static str {
        self.name
    }

    fn routes(&self) -> Vec<AuthRoute> {
        Vec::new()
    }

    fn schema(
        &self,
        declarations: &mut better_auth_core::plugin_runtime::ModelFields,
    ) -> AuthResult<()> {
        trace_lock(&self.events)?.push(format!("schema:{}", self.name));
        if self.name == "last" {
            let events = self.events.clone();
            declarations.register_user_fields(fields(
                "name",
                UserFieldConfig {
                    transform: Some(FieldTransforms {
                        input: Some(UserFieldTransform::new(move |value| {
                            trace_lock(&events)?.push("input:name".into());
                            Ok(format!(
                                "registered:{}",
                                required(value.as_str(), "Expected initialization user name")?
                            )
                            .into())
                        })),
                        ..Default::default()
                    }),
                    ..Default::default()
                },
            ));
            *trace_lock(&self.declarations)? = Some(declarations.clone());
        }
        Ok(())
    }

    async fn on_init(&self, context: &mut AuthInitContext<StatelessSchema>) -> AuthResult<()> {
        trace_lock(&self.events)?.push(format!("init:{}", self.name));
        if self.name == "first" {
            let user = context
                .database
                .create_user(
                    CreateUser::new()
                        .with_name("initializer")
                        .with_email("initializer@fields.test"),
                )
                .await?;
            let name = required(user.name.json()?, "Expected the initialization user name")?;
            trace_lock(&self.events)?.push(format!("return:{name}"));
            let missing = context
                .database
                .get_user_by_email("missing@fields.test")
                .await?
                .is_none();
            trace_lock(&self.events)?.push(format!("missing:{missing}"));
        }
        if self.fail {
            return Err(AuthError::bad_request("initialization stopped"));
        }
        Ok(())
    }

    async fn on_request(
        &self,
        _: &AuthRequest,
        _: &AuthContext<StatelessSchema>,
    ) -> AuthResult<Option<AuthResponse>> {
        Ok(None)
    }
}

#[tokio::test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "The lifecycle contract compares schema, initialization, and persisted adapter effects"
)]
async fn all_declarations_precede_initialization_and_failures_keep_completed_writes()
-> AuthResult<()> {
    for fail in [false, true] {
        let raw = memory();
        let events = Arc::new(Mutex::new(Vec::new()));
        let declarations = Arc::new(Mutex::new(None));
        let result = BetterAuth::new(config())
            .store_arc(raw.clone())
            .plugin(LifecycleFields {
                name: "first",
                events: events.clone(),
                declarations: declarations.clone(),
                fail,
            })
            .plugin(LifecycleFields {
                name: "last",
                events: events.clone(),
                declarations: declarations.clone(),
                fail: false,
            })
            .build()
            .await;
        let mut expected = vec![
            "schema:first",
            "schema:last",
            "init:first",
            "input:name",
            "return:\"registered:initializer\"",
            "missing:true",
        ];
        let history = required(
            trace_lock(&declarations)?.clone(),
            "Expected collected model declarations",
        )?;
        assert!(history.id_input_active(EntityRole::User)?);
        if fail {
            let error = result
                .err()
                .ok_or_else(|| AuthError::internal("Expected initialization failure"))?;
            assert!(matches!(&error, AuthError::BadRequest(_)));
            assert_eq!(error.instrumentation_message(), "initialization stopped");
        } else {
            let auth = result?;
            expected.push("init:last");
            let user = required(
                auth.store()
                    .get_user_by_email("initializer@fields.test")
                    .await?,
                "Expected initialized user through the final adapter",
            )?;
            assert_eq!(user.name.json()?, Some(json!("registered:initializer")));
            assert!(!history.id_input_active(EntityRole::User)?);
        }
        assert_eq!(*trace_lock(&events)?, expected);
        let user = raw
            .get_user_by_email("initializer@fields.test")
            .await?
            .ok_or_else(|| AuthError::internal("Initialization write disappeared"))?;
        assert_eq!(user.name.json()?, Some(json!("registered:initializer")));
    }
    Ok(())
}

fn prefix(prefix: &'static str) -> UserFieldConfig {
    UserFieldConfig {
        transform: Some(FieldTransforms {
            input: Some(UserFieldTransform::new(move |value| {
                Ok(match value {
                    FieldValue::Undefined => FieldValue::Undefined,
                    value => format!(
                        "{prefix}:{}",
                        required(value.as_str(), "Expected a string field callback value")?
                    )
                    .into(),
                })
            })),
            ..Default::default()
        }),
        ..Default::default()
    }
}

async fn core_contract<S: AuthSchema>(raw: Arc<dyn AuthStore<S>>) -> AuthResult<()> {
    for application in [false, true] {
        let expected = if application { "application" } else { "plugin" };
        let mut config = config();
        if application {
            let _ = config
                .user
                .fields_mut()
                .insert("name".into(), prefix("application"));
            let _ = config
                .session
                .fields_mut()
                .insert("userAgent".into(), prefix("application"));
            let _ = config
                .account
                .additional_fields
                .insert("scope".into(), prefix("application"));
            let _ = config
                .verification
                .additional_fields
                .insert("value".into(), prefix("application"));
        }
        let registrations = [
            (EntityRole::User, "name"),
            (EntityRole::Session, "userAgent"),
            (EntityRole::Account, "scope"),
            (EntityRole::Verification, "value"),
        ]
        .into_iter()
        .map(|(role, name)| (role, fields(name, prefix("plugin"))))
        .collect();
        let auth = BetterAuth::new(config)
            .store_arc(raw.clone())
            .plugin(Fields(registrations))
            .build()
            .await?;
        let user = auth
            .store()
            .create_user(
                CreateUser::new()
                    .with_name("User")
                    .with_email(format!("core-{expected}@fields.test")),
            )
            .await?;
        assert_eq!(user.name.json()?, Some(json!(format!("{expected}:User"))));
        let account = auth
            .store()
            .create_account(CreateAccount {
                user_id: user.id.clone(),
                provider_id: "ordinary".into(),
                account_id: format!("ordinary-account-{expected}").into(),
                scope: Some("Scope".into()).into(),
                ..Default::default()
            })
            .await?;
        assert_eq!(
            account.scope.json()?,
            Some(json!(format!("{expected}:Scope")))
        );
        let session = auth
            .store()
            .create_session(CreateSession {
                inherited_fields: Default::default(),
                user_id: user.id,
                expires_at: (chrono::Utc::now() + chrono::Duration::hours(1)).into(),
                ip_address: None,
                user_agent: Some("Agent".into()),
                impersonated_by: None,
                active_organization_id: None,
                additional_fields: [("userAgent".into(), "Agent".into())].into(),
            })
            .await?;
        assert_eq!(
            required(
                serde_json::to_value(session)?.get("userAgent"),
                "Expected the session userAgent field"
            )?,
            &json!(format!("{expected}:Agent"))
        );
        let verification = auth
            .store()
            .create_verification(CreateVerification {
                identifier: "ordinary".into(),
                value: "Value".into(),
                expires_at: (chrono::Utc::now() + chrono::Duration::hours(1)).into(),
                ..Default::default()
            })
            .await?;
        assert_eq!(
            verification.value.json()?,
            Some(json!(format!("{expected}:Value")))
        );
    }
    Ok(())
}

#[tokio::test]
async fn memory_core_registration_keeps_application_adapter_precedence() -> AuthResult<()> {
    core_contract(memory()).await
}
#[tokio::test]
async fn sqlite_core_registration_keeps_application_adapter_precedence() -> AuthResult<()> {
    core_contract(sqlite().await?).await
}

#[tokio::test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "Contract assertions report mismatches while setup and callback errors propagate"
)]
async fn builder_retains_application_user_fields_before_plugin_merge() -> AuthResult<()> {
    for application_enabled in [false, true] {
        let mut config = config();
        let default = |value: &'static str| UserFieldConfig {
            default_value: Some(value.into()),
            ..Default::default()
        };
        if application_enabled {
            config.user.fields_mut().extend([
                ("last".into(), default("application-last")),
                ("shared".into(), default("application-shared")),
                ("2".into(), default("two")),
                ("1".into(), default("one")),
                ("absent".into(), UserFieldConfig::default()),
            ]);
        }
        let defaults = Arc::new(Mutex::new(0));
        let observed_defaults = defaults.clone();
        let mut plugin = fields("pluginOnly", default("plugin-only"));
        let _ = plugin.fields_mut().insert(
            "shared".into(),
            UserFieldConfig {
                default_value_fn: Some(Arc::new(move || {
                    *trace_lock(&observed_defaults)? += 1;
                    Ok("plugin-shared".into())
                })),
                ..Default::default()
            },
        );
        let auth = BetterAuth::new(config)
            .store_arc(memory())
            .plugin(Fields(vec![(EntityRole::User, plugin)]))
            .build()
            .await?;
        let context = auth.context();
        let declarations = &required(
            context
                .extensions
                .get::<better_auth_core::plugin_runtime::ApplicationUserFields>(),
            "Builder did not retain application user declarations",
        )?
        .0;
        let expected_names: &[&str] = if application_enabled {
            &["last", "shared", "2", "1", "absent"]
        } else {
            &[]
        };
        assert_eq!(
            declarations
                .fields()
                .keys()
                .map(String::as_str)
                .collect::<Vec<_>>(),
            expected_names
        );
        assert_eq!(
            declarations
                .fields()
                .get("shared")
                .and_then(|field| field.default_value.as_ref()),
            application_enabled.then_some(&FieldValue::from("application-shared"))
        );
        let parsed = context.parse_user_input(&Default::default(), true)?;
        assert_eq!(
            parsed.get("shared"),
            Some(&FieldValue::from("plugin-shared"))
        );
        assert_eq!(
            parsed.get("pluginOnly"),
            Some(&FieldValue::from("plugin-only"))
        );
        let selected = context.select_application_user_fields(&parsed);
        let expected: FieldMap = if application_enabled {
            [
                ("1".into(), "one".into()),
                ("2".into(), "two".into()),
                ("last".into(), "application-last".into()),
                ("shared".into(), "plugin-shared".into()),
            ]
            .into()
        } else {
            FieldMap::new()
        };
        assert_eq!(selected, expected);
        assert_eq!(
            selected.keys().collect::<Vec<_>>(),
            expected.keys().collect::<Vec<_>>()
        );
        assert_eq!(*trace_lock(&defaults)?, 1);
    }
    Ok(())
}

#[tokio::test]
async fn native_replacement_declarations_initialize_for_registered_models() {
    for (role, name, field_type) in [
        (EntityRole::Passkey, "credential", UserFieldType::String),
        (EntityRole::Passkey, "name", UserFieldType::Json),
        (EntityRole::ApiKey, "key", UserFieldType::String),
        (EntityRole::ApiKey, "name", UserFieldType::Json),
        (EntityRole::RateLimit, "count", UserFieldType::Number),
    ] {
        let result = BetterAuth::new(config())
            .store_arc(memory())
            .plugin(Fields(vec![(
                role,
                fields(
                    name,
                    UserFieldConfig {
                        field_type,
                        ..Default::default()
                    },
                ),
            )]))
            .build()
            .await;
        let error = result.err();
        assert!(
            error.is_none(),
            "registration: {role:?}.{name}, expected successful initialization, got {error:?}"
        );
    }
}

#[test]
fn display_field_registration_preserves_omitted_empty_and_logical_aliases() {
    for (role, name) in [
        (EntityRole::Passkey, "name"),
        (EntityRole::Passkey, "aaguid"),
        (EntityRole::ApiKey, "name"),
        (EntityRole::DeviceCode, "scope"),
    ] {
        for alias in [None, Some(""), Some(name)] {
            let mut context = better_auth_core::plugin_runtime::ModelFields::default();
            let result = context.register_model_fields(
                role,
                fields(
                    name,
                    UserFieldConfig {
                        field_name: alias.map(str::to_owned),
                        ..Default::default()
                    },
                ),
            );
            assert!(
                result.is_ok(),
                "registration: {role:?}.{name}, alias={alias:?}: {result:?}"
            );
            let registered = context;
            let declared = registered.fields(role).fields();
            assert_eq!(declared.len(), 1);
            assert_eq!(
                declared.get(name).map(|field| field.field_name.as_deref()),
                Some(alias),
                "raw declaration: {role:?}.{name}, alias={alias:?}"
            );
        }
    }
}
