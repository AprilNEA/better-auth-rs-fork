#![cfg(feature = "seaorm2")]
#![expect(
    clippy::panic_in_result_fn,
    reason = "Deletion regressions assert persisted rows inside fallible database fixtures"
)]

//! `/delete-user` regressions on SQL stores.
//!
//! The upstream reference has no API-key cleanup, so these cases cover Rust-specific
//! behavior: an application without the API key plugin.

use std::collections::HashMap;

use better_auth::plugins::{EmailPasswordPlugin, UserManagementPlugin};
use better_auth::prelude::{AuthRequest, HttpMethod};
use better_auth::{AuthBuilder, AuthConfig, BetterAuth};
use better_auth_seaorm::SeaOrmStore;
use better_auth_seaorm::sea_orm::{
    ConnectOptions, ConnectionTrait, Database, DatabaseConnection, Statement,
};
use better_auth_seaorm::store::__private_test_support::{bundled_schema::BundledSchema, migrator};
use serde_json::{Value, json};

type TestError = Box<dyn std::error::Error + Send + Sync>;
type TestResult = Result<(), TestError>;

const EMAIL: &str = "delete-user@transaction.test";
const PASSWORD: &str = "delete-user-password";

#[derive(Clone, Copy, Debug)]
enum Fixture {
    /// The application does not register the API key plugin and has no `api_keys` table.
    WithoutApiKeyTable,
}

async fn send(
    auth: &BetterAuth<BundledSchema>,
    method: HttpMethod,
    path: &str,
    token: Option<&str>,
    body: Option<Value>,
) -> Result<(u16, Value), TestError> {
    let mut headers = HashMap::new();
    let _ = headers.insert("content-type".to_owned(), "application/json".to_owned());
    if let Some(token) = token {
        let _ = headers.insert("authorization".to_owned(), format!("Bearer {token}"));
    }
    let request = AuthRequest::from_parts(
        method,
        path.to_owned(),
        headers,
        body.map(|body| body.to_string().into_bytes()),
        None,
    );
    let response = auth.handle_request(request).await?;
    let status = response.status;
    let bytes = response.body.into_bytes()?;
    let body = if bytes.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&bytes)?
    };
    Ok((status, body))
}

async fn count(
    database: &DatabaseConnection,
    table: &str,
    column: &str,
    user_id: &str,
) -> Result<i64, TestError> {
    let row = database
        .query_one_raw(Statement::from_string(
            database.get_database_backend(),
            format!("SELECT COUNT(*) AS count FROM {table} WHERE {column} = '{user_id}'"),
        ))
        .await?
        .ok_or("COUNT returned no row")?;
    Ok(row.try_get::<i64>("", "count")?)
}

async fn check(database: DatabaseConnection, fixture: Fixture) -> TestResult {
    migrator::run_migrations(&database).await?;
    let _ = match fixture {
        Fixture::WithoutApiKeyTable => database.execute_unprepared("DROP TABLE api_keys").await?,
    };
    let mut config =
        AuthConfig::new("delete-user-transaction-secret-at-least-thirty-two-characters")
            .base_url("http://localhost:3000");
    config.session.bearer = Some(Default::default());
    let auth = AuthBuilder::new(config.clone())
        .store(SeaOrmStore::<BundledSchema>::new(config, database.clone()))
        .plugin(EmailPasswordPlugin::new().enable_signup(true))
        .plugin(UserManagementPlugin::new().delete_user_enabled(true))
        .build()
        .await?;

    let (status, signup) = send(
        &auth,
        HttpMethod::Post,
        "/sign-up/email",
        None,
        Some(json!({"email": EMAIL, "password": PASSWORD, "name": "Delete User"})),
    )
    .await?;
    assert_eq!(status, 200, "{fixture:?}: {signup}");
    let user_id = signup
        .pointer("/user/id")
        .and_then(Value::as_str)
        .ok_or("sign-up returned no user id")?
        .to_owned();
    let token = signup
        .get("token")
        .and_then(Value::as_str)
        .ok_or("sign-up returned no session token")?
        .to_owned();

    let (status, body) = send(
        &auth,
        HttpMethod::Post,
        "/delete-user",
        Some(&token),
        Some(json!({})),
    )
    .await?;
    let rows = (
        count(&database, "users", "id", &user_id).await?,
        count(&database, "sessions", "user_id", &user_id).await?,
        count(&database, "accounts", "user_id", &user_id).await?,
    );
    match fixture {
        Fixture::WithoutApiKeyTable => {
            // An inactive API key model must not reach its missing table.
            assert_eq!(status, 200, "{fixture:?}: {body}");
            assert_eq!(body.get("success"), Some(&Value::Bool(true)), "{body}");
            assert_eq!(rows, (0, 0, 0), "{fixture:?}");
        }
    }
    Ok(())
}

async fn sqlite(fixture: Fixture) -> TestResult {
    check(Database::connect("sqlite::memory:").await?, fixture).await
}

async fn live(backend: &'static str, fixture: Fixture) -> TestResult {
    let variable = if backend == "postgres" {
        "BETTER_AUTH_TEST_POSTGRES_URL"
    } else {
        "BETTER_AUTH_TEST_MYSQL_URL"
    };
    let mut options = ConnectOptions::new(std::env::var(variable)?);
    let _ = options.max_connections(1).sqlx_logging(false);
    let database = Database::connect(options).await?;
    let name = format!("ba_delete_user_{}", uuid::Uuid::new_v4().simple());
    let (create, select, drop) = if backend == "postgres" {
        (
            format!("CREATE SCHEMA {name}"),
            format!("SET search_path TO {name}"),
            format!("DROP SCHEMA {name} CASCADE"),
        )
    } else {
        (
            format!("CREATE DATABASE `{name}`"),
            format!("USE `{name}`"),
            format!("DROP DATABASE `{name}`"),
        )
    };
    let _ = database.execute_unprepared(&create).await?;
    let worker = database.clone();
    // A separate task preserves database cleanup when an assertion panics.
    let result = tokio::spawn(async move {
        let _ = worker.execute_unprepared(&select).await?;
        check(worker, fixture).await
    })
    .await;
    let cleanup = database.execute_unprepared(&drop).await;
    database.close().await?;
    let _ = cleanup?;
    result??;
    Ok(())
}

#[tokio::test]
async fn delete_user_without_api_key_table_deletes_the_user() -> TestResult {
    sqlite(Fixture::WithoutApiKeyTable).await
}

#[tokio::test]
#[ignore = "Requires BETTER_AUTH_TEST_POSTGRES_URL and isolated schema permissions"]
async fn live_postgres_delete_user_without_api_key_table_deletes_the_user() -> TestResult {
    live("postgres", Fixture::WithoutApiKeyTable).await
}

#[tokio::test]
#[ignore = "Requires BETTER_AUTH_TEST_MYSQL_URL and isolated database permissions"]
async fn live_mysql_delete_user_without_api_key_table_deletes_the_user() -> TestResult {
    live("mysql", Fixture::WithoutApiKeyTable).await
}
