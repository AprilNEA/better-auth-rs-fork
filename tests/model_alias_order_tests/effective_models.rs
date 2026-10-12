#![allow(
    clippy::expect_used,
    reason = "Fixture setup and response assertions require successful fallible construction."
)]
#![expect(
    clippy::panic_in_result_fn,
    reason = "The paired registration contract compares complete schema order and resolver results."
)]

use super::*;
use better_auth_core::{
    plugin_runtime::ModelFields,
    store::{ResolvedJoin, schema::SchemaConfiguration},
};

fn context(config: &AuthConfig) -> (AuthInitContext<StatelessSchema>, ModelFields) {
    let config = Arc::new(config.clone());
    (
        AuthInitContext::new(config.clone(), Arc::new(EphemeralStore::new(config)))
            .expect("fixture context initializes"),
        ModelFields::default(),
    )
}

fn declaration(events: &Events) -> UserConfig {
    UserConfig {
        additional_fields: Some(
            [(
                "marker".into(),
                UserFieldConfig {
                    transform: Some(FieldTransforms {
                        output: Some(events.output("declaration.marker")),
                        ..Default::default()
                    }),
                    ..Default::default()
                },
            )]
            .into(),
        ),
    }
}

fn finish(
    context: AuthInitContext<StatelessSchema>,
    mut fields: ModelFields,
    config: AuthConfig,
    plugins: Vec<&'static str>,
    secondary_storage: bool,
) -> ModelFields {
    let settings = SchemaConfiguration {
        config: Arc::new(config),
        plugins,
        metadata: context.metadata.clone(),
        secondary_storage,
        rate_limit: Default::default(),
    };
    fields.set_schema_configuration(&settings);
    fields
}

fn names(fields: &ModelFields) -> Vec<&'static str> {
    fields
        .active_models()
        .into_iter()
        .map(|(_, name)| name)
        .collect()
}

fn resolve(
    fields: &ModelFields,
    candidate: &str,
    role: EntityRole,
    name: &str,
) -> AuthResult<ResolvedJoin> {
    let parent = UserConfig {
        additional_fields: Some(
            [(
                "link".into(),
                UserFieldConfig {
                    references: Some(UserFieldReference {
                        model: candidate.into(),
                        field: "id".into(),
                        ..Default::default()
                    }),
                    ..Default::default()
                },
            )]
            .into(),
        ),
    };
    let child = UserConfig {
        additional_fields: Some([("id".into(), UserFieldConfig::default())].into()),
    };
    ResolvedJoin::resolve(
        (EntityRole::User, "user", &parent),
        (role, name, &child),
        fields,
        |role, candidate| match role {
            EntityRole::Session => candidate == "session_store",
            EntityRole::Verification => candidate == "verification_store",
            _ => false,
        },
    )
}

fn assert_resolves(
    fields: &ModelFields,
    candidate: &str,
    role: EntityRole,
    name: &str,
) -> AuthResult<()> {
    let actual = resolve(fields, candidate, role, name)?;
    assert_eq!(
        (
            actual.from,
            actual.to,
            actual.logical_from,
            actual.logical_to,
            actual.many
        ),
        (
            "link".into(),
            "id".into(),
            "link".into(),
            "id".into(),
            false
        ),
        "{candidate} must select {name}",
    );
    Ok(())
}

fn assert_error(
    fields: &ModelFields,
    candidate: &str,
    (role, name): (EntityRole, &str),
    message: String,
) -> AuthResult<()> {
    let error = resolve(fields, candidate, role, name)
        .err()
        .ok_or_else(|| AuthError::internal("Expected reference resolution failure"))?;
    assert!(matches!(error, AuthError::Config(_)));
    assert_eq!(error.instrumentation_message()?, message);
    Ok(())
}

#[test]
fn explicit_native_models_and_memory_rate_limit_keep_logical_names_and_aliases() -> AuthResult<()> {
    let config = AuthConfig::default();
    let (context, mut declarations) = context(&config);
    let events = Events::default();
    events.enabled.store(true, Ordering::Relaxed);
    for (role, alias) in [
        (EntityRole::Passkey, "key_store"),
        (EntityRole::RateLimit, "counter_store"),
    ] {
        declarations.register_model_schema(role, Some(alias), declaration(&events))?;
    }
    let fields = finish(context, declarations, config, vec![], false);
    assert_eq!(
        names(&fields),
        [
            "user",
            "session",
            "account",
            "verification",
            "passkey",
            "rateLimit"
        ]
    );
    for (role, name, alias) in [
        (EntityRole::Passkey, "passkey", "key_store"),
        (EntityRole::RateLimit, "rateLimit", "counter_store"),
    ] {
        assert_resolves(&fields, name, role, name)?;
        assert_resolves(&fields, alias, role, name)?;
        assert_eq!(fields.storage_model_name(role, name), alias);
        assert_eq!(
            fields
                .fields(role)
                .fields()
                .keys()
                .map(String::as_str)
                .collect::<Vec<_>>(),
            ["marker"]
        );
    }
    assert!(events.take()?.is_empty());
    Ok(())
}

#[tokio::test]
async fn organization_role_visibility_keeps_explicit_declarations_and_alias_priority()
-> AuthResult<()> {
    for explicit_before in [false, true] {
        for enabled in [false, true] {
            let config = AuthConfig::default();
            let (context, mut declarations) = context(&config);
            let events = Events::default();
            events.enabled.store(true, Ordering::Relaxed);
            if explicit_before {
                declarations.register_model_schema(
                    EntityRole::OrganizationRole,
                    Some("shared"),
                    declaration(&events),
                )?;
            }
            let mut organization = OrganizationConfig::default();
            organization.teams.enabled = true;
            organization.dynamic_access_control = enabled;
            let plugin = OrganizationPlugin::with_config(organization);
            AuthPlugin::<StatelessSchema>::schema(&plugin, &mut declarations)?;
            let mut context = context;
            plugin.on_init(&mut context).await?;
            if enabled {
                declarations.register_model_schema(
                    EntityRole::OrganizationRole,
                    Some("shared"),
                    UserConfig::default(),
                )?;
            }
            declarations.register_model_schema(
                EntityRole::Team,
                Some("shared"),
                UserConfig::default(),
            )?;
            let fields = finish(context, declarations, config, vec!["organization"], false);
            let mut expected = vec!["user", "session", "account", "verification"];
            if explicit_before {
                expected.push("organizationRole");
            }
            expected.push("organization");
            if enabled && !explicit_before {
                expected.push("organizationRole");
            }
            expected.extend(["team", "teamMember", "member", "invitation"]);
            assert_eq!(
                names(&fields),
                expected,
                "explicit={explicit_before}/enabled={enabled}"
            );
            let mut role_fields = if explicit_before {
                vec!["marker"]
            } else {
                vec![]
            };
            if enabled {
                role_fields.extend([
                    "organizationId",
                    "role",
                    "permission",
                    "createdAt",
                    "updatedAt",
                ]);
            }
            assert_eq!(
                fields
                    .fields(EntityRole::OrganizationRole)
                    .fields()
                    .keys()
                    .map(String::as_str)
                    .collect::<Vec<_>>(),
                role_fields
            );
            assert_resolves(&fields, "team", EntityRole::Team, "team")?;
            if explicit_before || enabled {
                assert_resolves(
                    &fields,
                    "organizationRole",
                    EntityRole::OrganizationRole,
                    "organizationRole",
                )?;
                assert_resolves(
                    &fields,
                    "shared",
                    EntityRole::OrganizationRole,
                    "organizationRole",
                )?;
                assert_error(&fields, "shared", (EntityRole::Team, "team"), "No foreign key found for model team and base model user while performing join operation.".into())?;
            } else {
                assert_resolves(&fields, "shared", EntityRole::Team, "team")?;
                assert_error(
                    &fields,
                    "organizationRole",
                    (EntityRole::OrganizationRole, "organizationRole"),
                    "Model \"organizationRole\" not found in schema".into(),
                )?;
            }
            assert!(events.take()?.is_empty());
        }
    }
    Ok(())
}

#[test]
fn secondary_storage_hides_explicit_core_declarations_until_database_storage_is_enabled()
-> AuthResult<()> {
    for store_core in [false, true] {
        let mut config = AuthConfig::default();
        config.session.store_session_in_database = Some(store_core);
        config.verification.store_in_database = store_core;
        let (context, mut declarations) = context(&config);
        let events = Events::default();
        events.enabled.store(true, Ordering::Relaxed);
        for role in [EntityRole::Session, EntityRole::Verification] {
            declarations.register_model_fields(role, declaration(&events))?;
        }
        let fields = finish(context, declarations, config, vec![], true);
        assert_eq!(
            names(&fields),
            if store_core {
                vec!["user", "session", "account", "verification"]
            } else {
                vec!["user", "account"]
            }
        );
        for (role, name, alias) in [
            (EntityRole::Session, "session", "session_store"),
            (
                EntityRole::Verification,
                "verification",
                "verification_store",
            ),
        ] {
            for candidate in [name, alias] {
                if store_core {
                    assert_resolves(&fields, candidate, role, name)?;
                } else {
                    assert_error(
                        &fields,
                        candidate,
                        (role, name),
                        format!("Model \"{candidate}\" not found in schema"),
                    )?;
                }
            }
        }
        assert!(events.take()?.is_empty());
    }
    Ok(())
}

#[test]
fn plugin_names_do_not_declare_models_but_explicit_empty_schemas_do() -> AuthResult<()> {
    for declared in [false, true] {
        let config = AuthConfig::default();
        let (context, mut declarations) = context(&config);
        if declared {
            declarations.register_model_fields(EntityRole::Passkey, UserConfig::default())?;
        }
        let fields = finish(context, declarations, config, vec!["passkey"], false);
        let mut expected = vec!["user", "session", "account", "verification"];
        if declared {
            expected.push("passkey");
        }
        assert_eq!(names(&fields), expected);
        if declared {
            assert_resolves(&fields, "passkey", EntityRole::Passkey, "passkey")?;
        } else {
            assert_error(
                &fields,
                "passkey",
                (EntityRole::Passkey, "passkey"),
                "Model \"passkey\" not found in schema".into(),
            )?;
        }
    }
    Ok(())
}
