use super::{Trace, record, take_trace};
use better_auth_core::{
    AuthConfig, AuthError, AuthResult, AuthStore, FieldFunction, FieldMap, FieldValue, SchemaValue,
    store::{ApiKeyUsageWrite, RuntimeStore, schema::EntityRole},
    user_fields::{
        FieldTransforms, UserConfig, UserFieldConfig, UserFieldTransform, UserFieldType,
    },
};
use better_auth_seaorm::{
    SeaOrmStore,
    sea_orm::{
        ActiveModelTrait, ConnectOptions, ConnectionTrait, Database, DatabaseConnection, DbBackend,
        EntityTrait, QueryOrder, Schema, Set,
    },
    store::{
        __private_test_support::bundled_schema::BundledSchema,
        entities::{api_key, two_factor},
    },
};
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};
use tracing::{Subscriber, instrument::WithSubscriber, span::Id};
use tracing_subscriber::{
    Layer,
    layer::{Context, SubscriberExt},
    registry::LookupSpan,
};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

#[derive(Clone, Copy, Debug)]
enum Model {
    ApiKey,
    TwoFactor,
}

#[derive(Debug, PartialEq)]
enum Stored {
    ApiKey(Vec<api_key::Model>),
    TwoFactor(Vec<two_factor::Model>),
}

impl Model {
    fn role(self) -> EntityRole {
        match self {
            Self::ApiKey => EntityRole::ApiKey,
            Self::TwoFactor => EntityRole::TwoFactor,
        }
    }

    fn field(self) -> (&'static str, UserFieldType) {
        match self {
            Self::ApiKey => ("remaining", UserFieldType::Number),
            Self::TwoFactor => ("backupCodes", UserFieldType::String),
        }
    }

    async fn seed(self, database: &DatabaseConnection) -> TestResult {
        let schema = Schema::new(database.get_database_backend());
        let table = match self {
            Self::ApiKey => schema.create_table_from_entity(api_key::Entity),
            Self::TwoFactor => schema.create_table_from_entity(two_factor::Entity),
        };
        let _ = database.execute(&table).await?;
        let at = "2030-01-01T00:00:00Z".parse::<chrono::DateTime<chrono::Utc>>()?;
        for id in ["target", "retained"] {
            match self {
                Self::ApiKey => {
                    let _ = api_key::ActiveModel {
                        id: Set(id.into()),
                        key_hash: Set(format!("{id}-key")),
                        reference_id: Set(format!("{id}-owner")),
                        config_id: Set("default".into()),
                        enabled: Set(true),
                        rate_limit_enabled: Set(false),
                        remaining: Set(Some(6.0)),
                        created_at: Set(at),
                        updated_at: Set(at),
                        ..Default::default()
                    }
                    .insert(database)
                    .await?;
                }
                Self::TwoFactor => {
                    let _ = two_factor::ActiveModel {
                        id: Set(id.into()),
                        secret: Set(format!("{id}-secret")),
                        backup_codes: Set("backup-before".into()),
                        user_id: Set(format!("{id}-owner")),
                        verified: Set(true),
                        failed_verification_count: Set(0),
                        locked_until: Set(None),
                        created_at: Set(at),
                        updated_at: Set(at),
                    }
                    .insert(database)
                    .await?;
                }
            }
        }
        Ok(())
    }

    async fn snapshot(self, database: &DatabaseConnection) -> TestResult<Stored> {
        Ok(match self {
            Self::ApiKey => Stored::ApiKey(
                api_key::Entity::find()
                    .order_by_asc(api_key::Column::Id)
                    .all(database)
                    .await?,
            ),
            Self::TwoFactor => Stored::TwoFactor(
                two_factor::Entity::find()
                    .order_by_asc(two_factor::Column::Id)
                    .all(database)
                    .await?,
            ),
        })
    }

    async fn write(
        self,
        store: &dyn AuthStore<BundledSchema>,
        selector: FieldValue,
        stale: bool,
    ) -> AuthResult<bool> {
        let id = SchemaValue::from_field(selector);
        match self {
            Self::ApiKey => {
                let at = "2031-01-01T00:00:00Z"
                    .parse::<chrono::DateTime<chrono::Utc>>()
                    .map_err(|error| AuthError::internal(error.to_string()))?;
                store
                    .write_api_key_usage(
                        &id,
                        ApiKeyUsageWrite::Refill {
                            previous: if stale { at.into() } else { FieldValue::Null },
                            remaining: 7.0,
                            at,
                        },
                    )
                    .await
                    .map(|row| row.is_some())
            }
            Self::TwoFactor => {
                store
                    .compare_exchange_two_factor_backup_codes(
                        &id,
                        &FieldValue::from(if stale { "stale" } else { "backup-before" }),
                        "backup-after".into(),
                    )
                    .await
            }
        }
    }
}

fn rejecting(trace: &Trace, allocation: &Arc<AtomicUsize>, phase: &'static str) -> FieldValue {
    let trace = trace.clone();
    let allocation = allocation.clone();
    FieldFunction::contextual(move |_, _| {
        record(&trace, phase)?;
        let message = format!("increment-{phase}-error");
        allocation.store(message.as_ptr() as usize, Ordering::SeqCst);
        Err(AuthError::Internal(message))
    })
    .into()
}

fn runtime(
    model: Model,
    database: &DatabaseConnection,
    trace: &Trace,
    set: FieldValue,
) -> AuthResult<Arc<dyn AuthStore<BundledSchema>>> {
    let input_trace = trace.clone();
    let output_trace = trace.clone();
    let (field, field_type) = model.field();
    let fields = UserConfig {
        additional_fields: Some(
            [(
                field.into(),
                UserFieldConfig {
                    field_type,
                    transform: Some(FieldTransforms {
                        input: Some(UserFieldTransform::new(move |_| {
                            record(&input_trace, "set-input")?;
                            Ok(set.clone())
                        })),
                        output: Some(UserFieldTransform::new(move |value| {
                            record(&output_trace, "set-output")?;
                            Ok(value)
                        })),
                    }),
                    ..Default::default()
                },
            )]
            .into(),
        ),
    };
    let config = Arc::new(AuthConfig::default());
    let raw = Arc::new(SeaOrmStore::<BundledSchema>::new(
        config.clone(),
        database.clone(),
    ));
    let mut model_fields = better_auth_core::plugin_runtime::ModelFields::default();
    model_fields.register_model_fields(model.role(), fields)?;
    raw.with_runtime(config, Vec::new(), model_fields)
}

struct Transactions(Trace);

impl<S: Subscriber + for<'a> LookupSpan<'a>> Layer<S> for Transactions {
    #[expect(
        clippy::expect_used,
        reason = "The test observer must fail if a transaction span or trace cannot be read"
    )]
    fn on_close(&self, id: Id, context: Context<'_, S>) {
        let span = context.span(&id).expect("completed transaction span");
        let metadata = span.metadata();
        if metadata.target() == "sea_orm::database::transaction"
            && matches!(metadata.name(), "begin" | "commit" | "rollback")
        {
            record(&self.0, metadata.name()).expect("transaction trace");
        }
    }
}

#[expect(
    clippy::expect_used,
    reason = "SQL metric callbacks cannot return errors; a poisoned test trace must fail"
)]
fn capture_sql(database: &mut DatabaseConnection, trace: &Trace) {
    let trace = trace.clone();
    database.set_metric_callback(move |info| {
        let phase = if info
            .statement
            .sql
            .to_ascii_uppercase()
            .ends_with(" FOR UPDATE")
        {
            "lock"
        } else {
            "unexpected-sql"
        };
        record(&trace, phase).expect("SQL trace");
    });
}

async fn check(mut database: DatabaseConnection) -> TestResult {
    let backend = database.get_database_backend();
    for model in [Model::ApiKey, Model::TwoFactor] {
        model.seed(&database).await?;
        let before = model.snapshot(&database).await?;
        for scenario in ["where-parse", "where-driver", "missing", "stale", "matched"] {
            if backend == DbBackend::MySql && scenario == "where-driver" {
                continue;
            }
            let trace = Trace::default();
            capture_sql(&mut database, &trace);
            let set_allocation = Arc::new(AtomicUsize::new(0));
            let where_allocation = Arc::new(AtomicUsize::new(0));
            let set = rejecting(&trace, &set_allocation, "set");
            let store = runtime(model, &database, &trace, set)?;
            let selector = match scenario {
                "where-parse" => rejecting(&trace, &where_allocation, "where"),
                "where-driver" => FieldMap::from([("driver-invalid".into(), true.into())]).into(),
                "missing" => "missing".into(),
                _ => "target".into(),
            };
            let result = model
                .write(store.as_ref(), selector, scenario == "stale")
                .with_subscriber(tracing_subscriber::registry().with(Transactions(trace.clone())))
                .await;
            let mut expected = vec!["set-input"];
            if backend == DbBackend::MySql {
                expected.push("begin");
                if scenario != "where-parse" {
                    expected.push("lock");
                }
            }
            if backend == DbBackend::MySql && matches!(scenario, "missing" | "stale") {
                assert!(!result?, "{model:?}/{scenario}");
                assert_eq!(set_allocation.load(Ordering::SeqCst), 0);
                expected.push("commit");
            } else {
                let phase = if scenario == "where-parse" {
                    "where"
                } else {
                    "set"
                };
                let Err(AuthError::Internal(message)) = result else {
                    return Err(AuthError::internal(format!(
                        "Expected {backend:?}/{model:?}/{scenario} original error: {result:?}"
                    ))
                    .into());
                };
                assert_eq!(message, format!("increment-{phase}-error"));
                let allocation = if phase == "where" {
                    &where_allocation
                } else {
                    &set_allocation
                };
                assert_eq!(message.as_ptr() as usize, allocation.load(Ordering::SeqCst));
                expected.push(phase);
                if backend == DbBackend::MySql {
                    expected.push("rollback");
                }
            }
            assert_eq!(
                take_trace(&trace)?,
                expected,
                "{backend:?}/{model:?}/{scenario}"
            );
            assert_eq!(
                model.snapshot(&database).await?,
                before,
                "{backend:?}/{model:?}/{scenario}"
            );
        }
    }
    Ok(())
}

#[tokio::test]
async fn sqlite_atomic_updates_parse_set_before_encoding_guards_even_without_a_match() -> TestResult
{
    let mut options = ConnectOptions::new("sqlite::memory:");
    let _ = options.max_connections(1);
    check(Database::connect(options).await?).await
}

#[tokio::test]
#[ignore = "Requires BETTER_AUTH_TEST_POSTGRES_URL and isolated schema permissions"]
async fn live_postgres_atomic_update_phases_keep_errors_and_complete_storage() -> TestResult {
    super::empty_in::isolated(DbBackend::Postgres, check).await
}

#[tokio::test]
#[ignore = "Requires BETTER_AUTH_TEST_MYSQL_URL and isolated database permissions"]
async fn live_mysql_atomic_update_phases_skip_unmatched_set_and_rollback_errors() -> TestResult {
    super::empty_in::isolated(DbBackend::MySql, check).await
}
