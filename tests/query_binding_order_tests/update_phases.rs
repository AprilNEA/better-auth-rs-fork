use super::{Trace, record, take_trace};
use better_auth_core::{
    AuthConfig, AuthError, AuthInitContext, AuthResult, AuthStore, FieldFunction, FieldMap,
    FieldValue, SchemaValue, UpdateUser,
    store::{RuntimeStore, schema::EntityRole},
    user_fields::{FieldTransforms, UserConfig, UserFieldConfig, UserFieldTransform},
};
use better_auth_seaorm::{
    SeaOrmStore,
    sea_orm::{
        ConnectOptions, ConnectionTrait, Database, DatabaseConnection, EntityTrait, QueryOrder,
        Schema,
    },
    store::{
        __private_test_support::bundled_schema::BundledSchema,
        entities::{api_key, passkey, user},
    },
};
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

type TestResult = Result<(), Box<dyn std::error::Error>>;

#[derive(Clone, Copy, Debug)]
enum Model {
    ApiKey,
    Passkey,
    User,
}

#[derive(Debug, PartialEq)]
enum Stored {
    ApiKey(Vec<api_key::Model>),
    Passkey(Vec<passkey::Model>),
    User(Vec<user::Model>),
}

impl Model {
    fn role(self) -> EntityRole {
        match self {
            Self::ApiKey => EntityRole::ApiKey,
            Self::Passkey => EntityRole::Passkey,
            Self::User => EntityRole::User,
        }
    }

    fn name(self) -> &'static str {
        match self {
            Self::ApiKey => "apikey",
            Self::Passkey => "passkey",
            Self::User => "user",
        }
    }

    async fn database(self) -> Result<DatabaseConnection, Box<dyn std::error::Error>> {
        let mut options = ConnectOptions::new("sqlite::memory:");
        let _ = options.max_connections(1);
        let database = Database::connect(options).await?;
        let schema = Schema::new(database.get_database_backend());
        let table = match self {
            Self::ApiKey => schema.create_table_from_entity(api_key::Entity),
            Self::Passkey => schema.create_table_from_entity(passkey::Entity),
            Self::User => schema.create_table_from_entity(user::Entity),
        };
        let _ = database.execute(&table).await?;
        let seed = match self {
            Self::ApiKey => {
                "INSERT INTO api_keys (id, name, key, reference_id, config_id, enabled, rate_limit_enabled, created_at, updated_at) \
                VALUES ('target', 'Before', 'target-key', 'owner', 'default', 1, 0, '2030-01-01T00:00:00.000Z', '2030-01-01T00:00:00.000Z'), \
                ('retained', 'Retained', 'other-key', 'other', 'default', 1, 0, '2030-01-01T00:00:00.000Z', '2030-01-01T00:00:00.000Z')"
            }
            Self::Passkey => {
                "INSERT INTO passkeys (id, name, public_key, user_id, credential_id, counter, device_type, backed_up, credential, created_at, updated_at) \
                VALUES ('target', 'Before', 'public-key', 'owner', 'credential', 0, 'singleDevice', 0, 'opaque-credential', '2030-01-01T00:00:00.000Z', '2030-01-01T00:00:00.000Z'), \
                ('retained', 'Retained', 'other-public-key', 'other', 'other-credential', 7, 'singleDevice', 1, 'other-opaque-credential', '2030-01-01T00:00:00.000Z', '2030-01-01T00:00:00.000Z')"
            }
            Self::User => {
                "INSERT INTO users (id, name, email, email_verified, created_at, updated_at) \
                VALUES ('target', 'Before', 'target@update-phases.test', 1, '2030-01-01T00:00:00.000Z', '2030-01-01T00:00:00.000Z'), \
                ('retained', 'Retained', 'other@update-phases.test', 0, '2030-01-01T00:00:00.000Z', '2030-01-01T00:00:00.000Z')"
            }
        };
        let _ = database.execute_unprepared(seed).await?;
        Ok(database)
    }

    async fn snapshot(
        self,
        database: &DatabaseConnection,
    ) -> Result<Stored, Box<dyn std::error::Error>> {
        Ok(match self {
            Self::ApiKey => Stored::ApiKey(
                api_key::Entity::find()
                    .order_by_asc(api_key::Column::Id)
                    .all(database)
                    .await?,
            ),
            Self::Passkey => Stored::Passkey(
                passkey::Entity::find()
                    .order_by_asc(passkey::Column::Id)
                    .all(database)
                    .await?,
            ),
            Self::User => Stored::User(
                user::Entity::find()
                    .order_by_asc(user::Column::Id)
                    .all(database)
                    .await?,
            ),
        })
    }

    async fn update(
        self,
        store: &dyn AuthStore<BundledSchema>,
        id: FieldValue,
        value: FieldValue,
    ) -> AuthResult<Option<FieldMap>> {
        let input = FieldMap::from([("name".into(), value.clone())]);
        match self {
            Self::ApiKey => {
                store
                    .update_api_key_record(&SchemaValue::from_field(id), input)
                    .await
            }
            Self::Passkey => {
                store
                    .update_passkey_record(&SchemaValue::from_field(id), input)
                    .await
            }
            Self::User => store
                .update_user_by_id_value(
                    &id,
                    UpdateUser {
                        name: SchemaValue::from_field(value),
                        ..Default::default()
                    },
                )
                .await
                .map(|row| row.map(FieldMap::from)),
        }
    }
}

fn runtime(
    model: Model,
    database: &DatabaseConnection,
    trace: &Trace,
    invalid_name: bool,
) -> AuthResult<Arc<dyn AuthStore<BundledSchema>>> {
    let input_trace = trace.clone();
    let output_trace = trace.clone();
    let mut fields = UserConfig {
        additional_fields: Some(
            [(
                "name".into(),
                UserFieldConfig {
                    transform: Some(FieldTransforms {
                        input: Some(UserFieldTransform::new(move |value| {
                            record(&input_trace, "name-input")?;
                            Ok(value)
                        })),
                        output: Some(UserFieldTransform::new(move |value| {
                            record(&output_trace, "name-output")?;
                            Ok(value)
                        })),
                    }),
                    ..Default::default()
                },
            )]
            .into(),
        ),
    };
    if invalid_name {
        let _ = fields.fields_mut().insert(
            "id".into(),
            UserFieldConfig {
                field_name: Some("old_id".into()),
                ..Default::default()
            },
        );
    }
    let mut config = AuthConfig::default();
    if matches!(model, Model::User) {
        config.user = fields.clone();
    }
    let config = Arc::new(config);
    let raw = Arc::new(SeaOrmStore::<BundledSchema>::new(
        config.clone(),
        database.clone(),
    ));
    let mut init = AuthInitContext::new(config.clone(), raw.clone());
    if !matches!(model, Model::User) {
        init.register_model_fields(model.role(), fields)?;
    }
    raw.with_runtime(config, Vec::new(), init.into_parts().plugin_fields)
}

fn rejecting(trace: &Trace, allocation: &Arc<AtomicUsize>, phase: &'static str) -> FieldValue {
    let trace = trace.clone();
    let allocation = allocation.clone();
    FieldFunction::contextual(move |_, _| {
        record(&trace, phase)?;
        let message = format!("update-{phase}-error");
        allocation.store(message.as_ptr() as usize, Ordering::SeqCst);
        Err(AuthError::Internal(message))
    })
    .into()
}

#[tokio::test]
async fn ordinary_updates_keep_name_parse_and_driver_phase_order() -> TestResult {
    for model in [Model::ApiKey, Model::Passkey, Model::User] {
        for scenario in [
            "where-name",
            "set-before-where",
            "where-before-driver",
            "set-before-driver",
            "missing-row",
        ] {
            let database = model.database().await?;
            let before = model.snapshot(&database).await?;
            let trace = Trace::default();
            let set_allocation = Arc::new(AtomicUsize::new(0));
            let where_allocation = Arc::new(AtomicUsize::new(0));
            let store = runtime(model, &database, &trace, scenario == "where-name")?;
            let set_callback = rejecting(&trace, &set_allocation, "set");
            let where_callback = rejecting(&trace, &where_allocation, "where");
            let invalid = FieldMap::from([("driver-invalid".into(), true.into())]);
            let (set, selector) = match scenario {
                "where-before-driver" => (invalid.into(), where_callback),
                "set-before-driver" => (set_callback, invalid.into()),
                "missing-row" => (set_callback, "missing".into()),
                _ => (set_callback, where_callback),
            };
            let result = model.update(store.as_ref(), selector, set).await;
            if scenario == "where-name" {
                let Err(AuthError::Config(message)) = result else {
                    return Err(AuthError::internal(format!(
                        "Expected {model:?} WHERE name error: {result:?}"
                    ))
                    .into());
                };
                assert_eq!(
                    message,
                    format!("Field old_id not found in model {}", model.name())
                );
                assert_eq!(take_trace(&trace)?, ["name-input"]);
                assert_eq!(set_allocation.load(Ordering::SeqCst), 0);
                assert_eq!(where_allocation.load(Ordering::SeqCst), 0);
            } else {
                let phase = if scenario == "where-before-driver" {
                    "where"
                } else {
                    "set"
                };
                let Err(AuthError::Internal(message)) = result else {
                    return Err(AuthError::internal(format!(
                        "Expected {model:?} {scenario} original error: {result:?}"
                    ))
                    .into());
                };
                assert_eq!(message, format!("update-{phase}-error"));
                let allocation = if phase == "where" {
                    &where_allocation
                } else {
                    &set_allocation
                };
                assert_eq!(message.as_ptr() as usize, allocation.load(Ordering::SeqCst));
                assert_eq!(take_trace(&trace)?, ["name-input", phase]);
            }
            assert_eq!(
                model.snapshot(&database).await?,
                before,
                "{model:?} {scenario}"
            );
        }
    }
    Ok(())
}
