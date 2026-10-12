use crate::store::{SeaOrmStore, bundled_schema::BundledSchema, map_db_err};
use better_auth_core::{
    AuthConfig, AuthError, AuthRecordFields, AuthResult, FieldMap, FieldValue, FromFieldMap,
    SchemaValue,
    store::{
        PasskeyStore, TwoFactorStore,
        schema::{EntityRole, SchemaConfiguration},
    },
    user_fields::{
        FieldTransforms, UserConfig, UserFieldConfig, UserFieldTransform, UserFieldType,
    },
};
use sea_orm::{ConnectionTrait, Database, DatabaseConnection, Statement};
use std::sync::{
    Arc, Mutex, MutexGuard,
    atomic::{AtomicBool, Ordering},
};

mod organization;
mod passkey;
mod projection;
mod two_factor;

const INITIAL: &str = "2000-01-01T00:00:00.000Z";
const FIRST: &str = "2001-02-03T04:05:06.000Z";
const NEXT: &str = "2002-03-04T05:06:07.000Z";
const LAST: &str = "2003-04-05T06:07:08.000Z";

type Event = (&'static str, &'static str, FieldValue);

#[derive(Clone, Default)]
struct Trace {
    events: Arc<Mutex<Vec<Event>>>,
    discard: Arc<AtomicBool>,
    discard_output: Arc<AtomicBool>,
    reject: Arc<AtomicBool>,
}

impl Trace {
    fn events(&self) -> AuthResult<MutexGuard<'_, Vec<Event>>> {
        self.events
            .lock()
            .map_err(|_| AuthError::internal("Legacy callback lock is poisoned"))
    }

    fn take(&self) -> AuthResult<Vec<Event>> {
        Ok(std::mem::take(&mut *self.events()?))
    }

    fn alias(&self, name: &'static str, column: &str) -> UserFieldConfig {
        let input = self.clone();
        let output = self.clone();
        UserFieldConfig {
            field_name: Some(column.into()),
            transform: Some(FieldTransforms {
                input: Some(UserFieldTransform::new(move |value| {
                    input.events()?.push(("input", name, value.clone()));
                    if input.discard.load(Ordering::SeqCst) {
                        Ok(FieldValue::Undefined)
                    } else if name == "name" {
                        Ok(format!(
                            "stored:{}",
                            SchemaValue::<String>::from_field(value).display_string()?
                        )
                        .into())
                    } else {
                        Ok(value)
                    }
                })),
                output: Some(UserFieldTransform::new(move |value| {
                    output.events()?.push(("output", name, value.clone()));
                    if output.reject.load(Ordering::SeqCst) {
                        return Err(AuthError::internal("declared-output-stop"));
                    }
                    if output.discard_output.load(Ordering::SeqCst) {
                        return Ok(FieldValue::Undefined);
                    }
                    Ok(format!(
                        "visible:{}",
                        SchemaValue::<String>::from_field(value).display_string()?
                    )
                    .into())
                })),
            }),
            ..Default::default()
        }
    }
}

async fn store(
    role: EntityRole,
    sql: &str,
    fields: Vec<(&str, UserFieldConfig)>,
) -> AuthResult<SeaOrmStore<BundledSchema>> {
    let database = Database::connect("sqlite::memory:")
        .await
        .map_err(map_db_err)?;
    let _ = database.execute_unprepared(sql).await.map_err(map_db_err)?;
    let mut store = SeaOrmStore::<BundledSchema>::new(
        AuthConfig::new("legacy-private-fields-secret-at-least-thirty-two-characters"),
        database,
    );
    let mut model_fields = better_auth_core::plugin_runtime::ModelFields::default();
    model_fields.register_model_fields(
        role,
        UserConfig {
            additional_fields: Some(
                fields
                    .into_iter()
                    .map(|(name, field)| (name.into(), field))
                    .collect(),
            ),
        },
    )?;
    store.model_fields = model_fields;
    store
        .model_fields
        .set_schema_configuration(&SchemaConfiguration {
            config: store.config.clone(),
            plugins: Vec::new(),
            metadata: Default::default(),
            secondary_storage: false,
            rate_limit: Default::default(),
        });
    Ok(store)
}

async fn stored(
    database: &DatabaseConnection,
    table: &str,
    columns: &[&str],
) -> AuthResult<FieldMap> {
    let row = database
        .query_one_raw(Statement::from_string(
            database.get_database_backend(),
            format!("SELECT * FROM {table}"),
        ))
        .await
        .map_err(map_db_err)?
        .ok_or_else(|| AuthError::internal("Expected the Legacy physical row"))?;
    columns
        .iter()
        .map(|column| Ok(((*column).into(), super::value(&row, column)?)))
        .collect()
}

fn assert_declared_stop(error: AuthError) {
    assert!(matches!(error, AuthError::Internal(message) if message == "declared-output-stop"));
}
