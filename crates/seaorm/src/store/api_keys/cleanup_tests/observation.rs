use super::*;
use sea_orm::sqlx::{Column, Row};

const MODELS: [&str; 5] = ["user", "session", "account", "verification", "apikey"];

pub(super) fn record(events: &Trace, value: JsonValue) -> AuthResult<()> {
    events
        .lock()
        .map_err(|_| AuthError::internal("SQL cleanup trace lock is poisoned"))?
        .push(value);
    Ok(())
}

// Apply the source capture's JSON.stringify boundary without changing database value types or fields.
fn json_observation(value: JsonValue) -> AuthResult<JsonValue> {
    Ok(serde_json::from_str(
        &better_auth_core::utils::json::stringify(&value)?,
    )?)
}

fn assert_observation(actual: &JsonValue, expected: &JsonValue, path: &str) {
    match (actual, expected) {
        (JsonValue::Object(actual), JsonValue::Object(expected)) => {
            assert_eq!(
                actual.keys().collect::<Vec<_>>(),
                expected.keys().collect::<Vec<_>>(),
                "{path}: object key order"
            );
            for ((name, actual), (_, expected)) in actual.iter().zip(expected) {
                assert_observation(actual, expected, &format!("{path}/{name}"));
            }
        }
        (JsonValue::Array(actual), JsonValue::Array(expected)) => {
            assert_eq!(actual.len(), expected.len(), "{path}: array length");
            for (index, (actual, expected)) in actual.iter().zip(expected).enumerate() {
                assert_observation(actual, expected, &format!("{path}/{index}"));
            }
        }
        _ => assert_eq!(actual, expected, "{path}: value"),
    }
}

async fn rows(database: &DatabaseConnection, sql: &str) -> AuthResult<JsonValue> {
    let backend = database.get_database_backend();
    let mut records = Vec::new();
    for row in database
        .query_all_raw(Statement::from_string(backend, sql))
        .await
        .map_err(map_db_err)?
    {
        let columns = match backend {
            DbBackend::Sqlite => required(row.try_as_sqlite_row())?
                .columns()
                .iter()
                .map(|column| column.name())
                .collect::<Vec<_>>(),
            DbBackend::Postgres => required(row.try_as_pg_row())?
                .columns()
                .iter()
                .map(|column| column.name())
                .collect(),
            DbBackend::MySql => required(row.try_as_mysql_row())?
                .columns()
                .iter()
                .map(|column| column.name())
                .collect(),
        };
        let fields = columns
            .into_iter()
            .map(|column| {
                Ok((
                    column.to_owned(),
                    values::observe(&crate::store::plugin_rows::value(&row, column)?)?,
                ))
            })
            .collect::<AuthResult<serde_json::Map<_, _>>>()?;
        records.push(JsonValue::Object(fields));
    }
    json_observation(JsonValue::Array(records))
}

pub(super) async fn stored(database: &DatabaseConnection) -> AuthResult<JsonValue> {
    let backend = database.get_database_backend();
    let quote = if backend == DbBackend::MySql {
        '`'
    } else {
        '"'
    };
    let mut tables = serde_json::Map::new();
    for model in MODELS {
        let records = rows(
            database,
            &format!("SELECT * FROM {quote}{model}{quote} ORDER BY {quote}id{quote}"),
        )
        .await?;
        let _ = tables.insert(model.into(), records);
    }
    json_observation(JsonValue::Object(tables))
}

#[expect(
    clippy::panic_in_result_fn,
    reason = "Contract assertions compare complete outcomes while database observation errors propagate through Result."
)]
pub(super) async fn check(
    database: &DatabaseConnection,
    events: &Trace,
    before: &JsonValue,
    result: AuthResult<JsonValue>,
    expected: &JsonValue,
    backend: &str,
    deletion: bool,
) -> AuthResult<()> {
    let trace = std::mem::take(
        &mut *events
            .lock()
            .map_err(|_| AuthError::internal("SQL cleanup trace lock is poisoned"))?,
    );
    assert_observation(
        before,
        &expected["before"],
        &format!("{backend}: before operation"),
    );
    assert_observation(
        &stored(database).await?,
        &expected["after"],
        &format!("{backend}: after operation"),
    );
    assert_observation(
        &json_observation(json!(trace))?,
        &expected["events"],
        &format!("{backend}: callbacks"),
    );
    assert_eq!(
        json!(result.is_ok()),
        expected["returned"],
        "{backend}: return/error: {result:?}"
    );
    match result {
        Ok(result) => {
            assert!(expected.get("error").is_none());
            assert_observation(
                &json_observation(result)?,
                &expected["result"],
                &format!("{backend}: complete result"),
            );
        }
        Err(AuthError::Database(better_auth_core::error::DatabaseError::Query(actual))) => {
            let error = &expected["error"];
            let message = required(error["message"].as_str())?;
            let raw = &error["raw"]["root"];
            assert_eq!(raw["type"], "error");
            assert_eq!(raw["error"]["message"], message);
            assert!(raw["error"]["stack"].is_string());
            let kind = if deletion || backend == "mysql" {
                "Execution"
            } else {
                "Query"
            };
            let expected_message = if backend == "mysql" {
                assert_eq!(error["name"], "Error");
                let properties = required(raw["properties"].as_array())?;
                let property = |name: &str| -> AuthResult<&JsonValue> {
                    Ok(
                        &required(properties.iter().find(|property| property[0] == name))?[1]["value"],
                    )
                };
                format!(
                    "{kind} Error: error returned from database: {} ({}): {message}",
                    property("errno")?,
                    required(property("sqlState")?.as_str())?
                )
            } else {
                assert_eq!(backend, "postgres");
                assert_eq!(error["name"], "error");
                format!("{kind} Error: error returned from database: {message}")
            };
            assert_eq!(
                actual, expected_message,
                "{backend}: database error boundary"
            );
        }
        Err(error) => return Err(error),
    }
    Ok(())
}

#[expect(
    clippy::panic_in_result_fn,
    reason = "The contract requires the captured foreign key setting before executing the original migration."
)]
pub(super) async fn migrate(
    database: &DatabaseConnection,
    case: &JsonValue,
    baseline: &JsonValue,
) -> AuthResult<()> {
    let backend = database.get_database_backend();
    let sql = if backend == DbBackend::Sqlite {
        let connection = if case["scenario"]["name"] == "mapped-serial-reference-valid" {
            case
        } else {
            required(
                required(baseline["connections"].as_array())?
                    .iter()
                    .find(|connection| connection["scenario"] == case["scenario"]),
            )?
        };
        let foreign_keys = if connection.get("environment").is_some() {
            &connection["environment"]["foreignKeys"]
        } else {
            &connection["foreignKeys"]
        };
        assert_eq!(required(foreign_keys.as_array())?.len(), 1);
        let enforcement = required(foreign_keys[0]["foreign_keys"].as_u64())?;
        assert!(enforcement <= 1);
        let _ = database
            .execute_unprepared(&format!("PRAGMA foreign_keys = {enforcement}"))
            .await
            .map_err(map_db_err)?;
        assert_observation(
            &rows(database, "PRAGMA foreign_keys").await?,
            foreign_keys,
            "SQLite foreign key enforcement",
        );
        required(if connection.get("migration").is_some() {
            connection["migration"]["initialSql"].as_str()
        } else {
            connection["initialSql"].as_str()
        })?
    } else {
        let environment = &baseline["cases"][0]["environment"];
        let (query, expected) = if backend == DbBackend::Postgres {
            (
                "SHOW session_replication_role",
                &environment["replicationRole"],
            )
        } else {
            (
                "SELECT @@FOREIGN_KEY_CHECKS AS foreignKeys",
                &environment["foreignKeys"],
            )
        };
        assert_observation(
            &rows(database, query).await?,
            expected,
            "Foreign key environment",
        );
        required(case["catalog"]["migration"]["initialSql"].as_str())?
    };
    let _ = database.execute_unprepared(sql).await.map_err(map_db_err)?;
    assert_eq!(
        stored(database).await?,
        json!({"user":[],"session":[],"account":[],"verification":[],"apikey":[]})
    );
    Ok(())
}

pub(super) async fn drop_tables(database: &DatabaseConnection) -> AuthResult<()> {
    let quote = if database.get_database_backend() == DbBackend::MySql {
        '`'
    } else {
        '"'
    };
    for model in ["apikey", "verification", "account", "session", "user"] {
        let _ = database
            .execute_unprepared(&format!("DROP TABLE {quote}{model}{quote}"))
            .await
            .map_err(map_db_err)?;
    }
    Ok(())
}
