use super::{Trace, record, take_trace};
use better_auth_core::{
    AuthConfig, AuthError, AuthInitContext, AuthRecordFields, AuthResult, AuthStore,
    DeviceCodeOwnership, DeviceCodeWhere, FieldMap, FieldValue,
    id::IdGeneration,
    organization_fields::OrganizationFields,
    store::{
        DeviceCodeStore, OrganizationRoleStore, OrganizationStore, RuntimeStore, schema::EntityRole,
    },
    user_fields::{
        FieldTransforms, UserConfig, UserFieldConfig, UserFieldReference, UserFieldTransform,
        UserFieldType,
    },
};
use better_auth_seaorm::{
    SeaOrmStore,
    sea_orm::{
        ConnectOptions, ConnectionTrait, Database, DatabaseConnection, EntityTrait, QueryOrder,
        Schema,
    },
    store::{
        __private_test_support::bundled_schema::BundledSchema,
        entities::{device_code, organization_role, wallet_address},
    },
};
use serde_json::json;
use std::sync::Arc;

type TestResult = Result<(), Box<dyn std::error::Error>>;

async fn database() -> Result<DatabaseConnection, Box<dyn std::error::Error>> {
    let mut options = ConnectOptions::new("sqlite::memory:");
    let _ = options.max_connections(1);
    Ok(Database::connect(options).await?)
}

fn runtime(
    database: &DatabaseConnection,
    config: AuthConfig,
    role: EntityRole,
    fields: UserConfig,
) -> AuthResult<Arc<dyn AuthStore<BundledSchema>>> {
    let config = Arc::new(config);
    let raw = Arc::new(SeaOrmStore::<BundledSchema>::new(
        config.clone(),
        database.clone(),
    ));
    let mut init = AuthInitContext::new(config.clone(), raw.clone());
    init.register_model_fields(role, fields)?;
    raw.with_runtime(config, Vec::new(), init.into_parts().plugin_fields)
}

fn callbacks(trace: &Trace, input: &'static str, output: &'static str) -> FieldTransforms {
    let input_trace = trace.clone();
    let output_trace = trace.clone();
    FieldTransforms {
        input: Some(UserFieldTransform::new(move |value| {
            record(&input_trace, input)?;
            Ok(value)
        })),
        output: Some(UserFieldTransform::new(move |value| {
            record(&output_trace, output)?;
            Ok(value)
        })),
    }
}

#[tokio::test]
async fn device_consumption_binds_every_operand_before_resolving_the_first_id_alias() -> TestResult
{
    for invalid_ownership in [false, true] {
        let database = database().await?;
        let _ = database
            .execute(
                &Schema::new(database.get_database_backend())
                    .create_table_from_entity(device_code::Entity),
            )
            .await?;
        let _ = database.execute_unprepared(
            "INSERT INTO device_code (id, device_code, user_code, user_id, expires_at, status, client_id, scope) \
             VALUES ('1', 'target-device', 'ABCD2345', 'owner', '2030-01-01T00:00:00.000Z', 'approved', 'client', '7'), \
             ('2', 'retained-device', 'EFGH2345', 'owner', '2030-01-01T00:00:00.000Z', 'approved', 'client', '9')",
        ).await?;
        let before = device_code::Entity::find()
            .order_by_asc(device_code::Column::Id)
            .all(&database)
            .await?;
        assert_eq!(before.len(), 2);
        // A separate runtime supplies the physical consumption snapshot without warming the tested ID schema.
        let reader = SeaOrmStore::<BundledSchema>::new(AuthConfig::default(), database.clone());
        let expected = reader
            .get_device_code_by_device_code("target-device")
            .await?
            .ok_or_else(|| AuthError::internal("Seed Device code is missing"))?;
        let trace = Trace::default();
        let mut config = AuthConfig::default();
        config.advanced.database.generate_id = Some(IdGeneration::Serial);
        let store = runtime(
            &database,
            config,
            EntityRole::DeviceCode,
            UserConfig {
                additional_fields: Some(
                    [
                        (
                            "id".into(),
                            UserFieldConfig {
                                field_name: Some("old_id".into()),
                                ..Default::default()
                            },
                        ),
                        (
                            "scope".into(),
                            UserFieldConfig {
                                references: Some(UserFieldReference {
                                    model: "user".into(),
                                    field: "id".into(),
                                    ..Default::default()
                                }),
                                transform: Some(callbacks(&trace, "scope-input", "scope-output")),
                                ..Default::default()
                            },
                        ),
                    ]
                    .into(),
                ),
            },
        )?;
        let value = if invalid_ownership {
            FieldMap::from([("toString".into(), FieldValue::Null)]).into()
        } else {
            FieldValue::from("7")
        };
        let result = store
            .consume_device_code(
                &expected,
                &DeviceCodeOwnership::Where(DeviceCodeWhere::new("scope", value)),
            )
            .await;
        if invalid_ownership {
            assert!(
                matches!(&result, Err(AuthError::TypeError(message)) if message == "No default value"),
                "{result:?}"
            );
        } else {
            assert!(
                matches!(&result, Err(AuthError::Config(message)) if message == "Field old_id not found in model deviceCode"),
                "{result:?}"
            );
        }
        assert_eq!(take_trace(&trace)?, Vec::<&str>::new());
        assert_eq!(
            device_code::Entity::find()
                .order_by_asc(device_code::Column::Id)
                .all(&database)
                .await?,
            before
        );

        let consumed = store
            .consume_device_code(
                &expected,
                &DeviceCodeOwnership::Where(DeviceCodeWhere::new("scope", "7")),
            )
            .await?
            .ok_or_else(|| {
                AuthError::internal("Canonical ID retry must consume the Device code")
            })?;
        assert_eq!(consumed.field_values()?, expected.field_values()?);
        assert_eq!(take_trace(&trace)?, ["scope-output"]);
        let retained: Vec<_> = before.into_iter().filter(|row| row.id == "2").collect();
        assert_eq!(
            device_code::Entity::find()
                .order_by_asc(device_code::Column::Id)
                .all(&database)
                .await?,
            retained
        );
    }
    Ok(())
}

#[tokio::test]
async fn wallet_mixed_aliases_resolve_twice_without_converting_operands_twice() -> TestResult {
    let database = database().await?;
    let _ = database
        .execute(
            &Schema::new(database.get_database_backend())
                .create_table_from_entity(wallet_address::Entity),
        )
        .await?;
    let _ = database
        .execute_unprepared(
            "INSERT INTO wallet_address (id, user_id, address, chain_id, is_primary, created_at) \
         VALUES ('mixed', 'owner', 'true', 1, 0, '2030-01-01T00:00:00.000Z'), \
         ('converted-twice', 'owner', '1', 1, 0, '2030-01-01T00:00:00.000Z')",
        )
        .await?;
    let before = wallet_address::Entity::find()
        .order_by_asc(wallet_address::Column::Id)
        .all(&database)
        .await?;
    assert_eq!(before.len(), 2);
    let trace = Trace::default();
    let store = runtime(
        &database,
        AuthConfig::default(),
        EntityRole::WalletAddress,
        UserConfig {
            additional_fields: Some(
                [
                    (
                        "address".into(),
                        UserFieldConfig {
                            field_name: Some("chainId".into()),
                            transform: Some(callbacks(&trace, "address-input", "address-output")),
                            ..Default::default()
                        },
                    ),
                    (
                        "chainId".into(),
                        UserFieldConfig {
                            field_type: UserFieldType::Boolean,
                            field_name: Some("address".into()),
                            transform: Some(callbacks(&trace, "chain-input", "chain-output")),
                            ..Default::default()
                        },
                    ),
                ]
                .into(),
            ),
        },
    )?;
    let returned = store
        .get_wallet_address_value(&"true".into(), Some(&"true".into()))
        .await?
        .ok_or_else(|| {
            AuthError::internal("Mixed aliases must select the original string address")
        })?;
    assert_eq!(
        serde_json::Value::Object(returned.field_values()?.json()?),
        json!({
            "id": "mixed", "userId": "owner", "address": 1, "chainId": "true",
            "isPrimary": false, "createdAt": "2030-01-01T00:00:00.000Z",
        })
    );
    assert_eq!(take_trace(&trace)?, ["address-output", "chain-output"]);
    assert_eq!(
        wallet_address::Entity::find()
            .order_by_asc(wallet_address::Column::Id)
            .all(&database)
            .await?,
        before
    );
    Ok(())
}

#[tokio::test]
async fn organization_role_names_convert_as_one_array_and_keep_the_organization_filter()
-> TestResult {
    let database = database().await?;
    let _ = database
        .execute(
            &Schema::new(database.get_database_backend())
                .create_table_from_entity(organization_role::Entity),
        )
        .await?;
    let _ = database.execute_unprepared(
        "INSERT INTO organization_role (id, organization_id, role, permission, created_at, updated_at) \
         VALUES ('numeric-name', 'target-org', '01', '{}', '2030-01-01T00:00:00.000Z', NULL), \
         ('text-name', 'target-org', 'literal', '{}', '2030-01-01T00:00:00.000Z', NULL), \
         ('converted-name', 'target-org', '1', '{}', '2030-01-01T00:00:00.000Z', NULL), \
         ('other-tenant', 'other-org', '01', '{}', '2030-01-01T00:00:00.000Z', NULL)",
    ).await?;
    let before = organization_role::Entity::find()
        .order_by_asc(organization_role::Column::Id)
        .all(&database)
        .await?;
    assert_eq!(before.len(), 4);
    let trace = Trace::default();
    let store = SeaOrmStore::<BundledSchema>::new(AuthConfig::default(), database.clone());
    store.configure_organization_fields(OrganizationFields {
        organization_role: UserConfig {
            additional_fields: Some(
                [(
                    "role".into(),
                    UserFieldConfig {
                        field_type: UserFieldType::Number,
                        transform: Some(callbacks(&trace, "role-input", "role-output")),
                        ..Default::default()
                    },
                )]
                .into(),
            ),
        },
        ..Default::default()
    })?;
    // A mixed numeric array stays unchanged; separate equality queries would convert "01" to 1.
    let returned = store
        .query_organization_roles("target-org", &["01".into(), "literal".into()])
        .await?;
    let returned = returned
        .iter()
        .map(|row| row.field_values()?.json().map(serde_json::Value::Object))
        .collect::<AuthResult<Vec<_>>>()?;
    assert_eq!(
        returned,
        [
            json!({ "id": "numeric-name", "organizationId": "target-org", "role": "01", "permission": "{}", "createdAt": "2030-01-01T00:00:00.000Z", "updatedAt": null }),
            json!({ "id": "text-name", "organizationId": "target-org", "role": "literal", "permission": "{}", "createdAt": "2030-01-01T00:00:00.000Z", "updatedAt": null }),
        ]
    );
    assert_eq!(take_trace(&trace)?, ["role-output", "role-output"]);
    assert_eq!(
        organization_role::Entity::find()
            .order_by_asc(organization_role::Column::Id)
            .all(&database)
            .await?,
        before
    );
    assert!(
        store
            .query_organization_roles("target-org", &[])
            .await?
            .is_empty()
    );
    assert_eq!(take_trace(&trace)?, Vec::<&str>::new());
    assert_eq!(
        organization_role::Entity::find()
            .order_by_asc(organization_role::Column::Id)
            .all(&database)
            .await?,
        before
    );
    Ok(())
}

#[tokio::test]
async fn organization_role_conditions_parse_before_driver_encoding() -> TestResult {
    use better_auth_core::{FieldFunction, UpdateOrganizationRole};
    use std::sync::atomic::{AtomicUsize, Ordering};

    let database = database().await?;
    let _ = database
        .execute(
            &Schema::new(database.get_database_backend())
                .create_table_from_entity(organization_role::Entity),
        )
        .await?;
    let _ = database.execute_unprepared(
        "INSERT INTO organization_role (id, organization_id, role, permission, created_at, updated_at) \
         VALUES ('selected', 'target-org', 'owner', '{}', '2030-01-01T00:00:00.000Z', NULL), \
         ('retained', 'other-org', 'member', '{}', '2030-01-01T00:00:00.000Z', NULL)",
    ).await?;
    let before = organization_role::Entity::find()
        .order_by_asc(organization_role::Column::Id)
        .all(&database)
        .await?;
    assert_eq!(before.len(), 2);
    let trace = Trace::default();
    let store = SeaOrmStore::<BundledSchema>::new(AuthConfig::default(), database.clone());
    store.configure_organization_fields(OrganizationFields {
        organization_role: UserConfig {
            additional_fields: Some(
                [(
                    "role".into(),
                    UserFieldConfig {
                        transform: Some(callbacks(&trace, "role-input", "role-output")),
                        ..Default::default()
                    },
                )]
                .into(),
            ),
        },
        ..Default::default()
    })?;
    for operation in ["find", "update", "delete"] {
        for array in [false, true] {
            let allocation = Arc::new(AtomicUsize::new(0));
            let original = allocation.clone();
            let rejected_trace = trace.clone();
            let rejecting = FieldValue::from(FieldFunction::contextual(move |_, _| {
                record(&rejected_trace, "rejecting")?;
                let message = "original-condition-error".to_owned();
                original.store(message.as_ptr() as usize, Ordering::SeqCst);
                Err(AuthError::Internal(message))
            }));
            let later_trace = trace.clone();
            let later = FieldValue::from(FieldFunction::contextual(move |_, _| {
                record(&later_trace, "later")?;
                Ok(FieldValue::Null)
            }));
            let selectors = FieldMap::from([
                (
                    "organizationId".into(),
                    FieldMap::from([("driver".into(), true.into())]).into(),
                ),
                (
                    "role".into(),
                    if array {
                        vec![rejecting].into()
                    } else {
                        rejecting
                    },
                ),
                ("permission".into(), later),
            ]);
            let result = match operation {
                "find" => store
                    .find_organization_role_by_fields(&selectors)
                    .await
                    .map(drop),
                "update" => store
                    .update_organization_roles(
                        &selectors,
                        UpdateOrganizationRole {
                            role: Some("Changed".into()),
                            ..Default::default()
                        },
                    )
                    .await
                    .map(drop),
                _ => store.delete_organization_role_by_fields(&selectors).await,
            };
            let Err(AuthError::Internal(message)) = result else {
                return Err(AuthError::internal("Expected the original condition error").into());
            };
            assert_eq!(message, "original-condition-error");
            assert_eq!(message.as_ptr() as usize, allocation.load(Ordering::SeqCst));
            assert_eq!(
                take_trace(&trace)?,
                if operation == "update" {
                    vec!["role-input", "rejecting"]
                } else {
                    vec!["rejecting"]
                }
            );
            assert_eq!(
                organization_role::Entity::find()
                    .order_by_asc(organization_role::Column::Id)
                    .all(&database)
                    .await?,
                before
            );
        }
    }
    Ok(())
}
