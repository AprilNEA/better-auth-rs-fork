use super::{BundledSchema, TestResult, server};
use better_auth_core::{
    AuthConfig, AuthError, AuthInitContext, AuthResult, AuthStore, DeviceCode, DeviceCodeOwnership,
    FieldMap, FieldValue, FromFieldMap,
    store::{
        VerificationStore,
        schema::{EntityRole, SchemaConfiguration},
        transaction,
    },
    user_fields::{
        FieldTransforms, UserConfig, UserFieldConfig, UserFieldTransform, UserFieldType,
    },
};
use better_auth_seaorm::{
    SeaOrmStore,
    sea_orm::{ConnectionTrait, Database, DatabaseConnection, Statement},
};
use std::sync::{
    Arc, Mutex, MutexGuard,
    atomic::{AtomicBool, AtomicUsize, Ordering},
};

#[path = "sparse_consume/device.rs"]
mod device;
#[path = "sparse_consume/verification.rs"]
mod verification;

type Events = Arc<Mutex<Vec<(&'static str, FieldValue)>>>;

fn events(events: &Events) -> AuthResult<MutexGuard<'_, Vec<(&'static str, FieldValue)>>> {
    events
        .lock()
        .map_err(|_| AuthError::internal("Sparse consume event lock is poisoned"))
}

async fn snapshot(
    database: &DatabaseConnection,
    table: &str,
    columns: &[&str],
) -> TestResult<Vec<FieldMap>> {
    database
        .query_all_raw(Statement::from_string(
            database.get_database_backend(),
            format!("SELECT * FROM {table} ORDER BY id"),
        ))
        .await?
        .into_iter()
        .map(|row| {
            columns
                .iter()
                .map(|column| {
                    let value = if *column == "expires_at" {
                        FieldValue::from(row.try_get::<f64>("", column)?)
                    } else {
                        FieldValue::from(row.try_get::<String>("", column)?)
                    };
                    Ok(((*column).into(), value))
                })
                .collect::<TestResult<FieldMap>>()
        })
        .collect()
}

async fn check(database: DatabaseConnection) -> TestResult {
    device::check(&database).await?;
    verification::check(&database).await
}

#[tokio::test]
async fn sqlite_sparse_consume_preserves_projections_guards_and_transaction_failures() -> TestResult
{
    check(Database::connect("sqlite::memory:").await?).await
}

#[tokio::test]
#[ignore = "Requires BETTER_AUTH_TEST_POSTGRES_URL and isolated schema permissions"]
async fn live_postgres_sparse_consume_preserves_projections_guards_and_transaction_failures()
-> TestResult {
    server::isolated("postgres", check).await
}

#[tokio::test]
#[ignore = "Requires BETTER_AUTH_TEST_MYSQL_URL and isolated database permissions"]
async fn live_mysql_sparse_consume_preserves_projections_guards_and_transaction_failures()
-> TestResult {
    server::isolated("mysql", check).await
}
