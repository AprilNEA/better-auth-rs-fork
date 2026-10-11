use super::*;
use better_auth_core::store::schema::EntityRole;
use better_auth_seaorm::sea_orm::{ConnectionTrait, Database, DbBackend, Statement};

pub(super) async fn sqlite(scenario: &Scenario) -> TestResult<DatabaseConnection> {
    let database = Database::connect("sqlite::memory:").await?;
    let _ = database
        .execute_raw(Statement::from_string(
            DbBackend::Sqlite,
            "PRAGMA foreign_keys = ON",
        ))
        .await?;
    let foreign_keys = database
        .query_one_raw(Statement::from_string(
            DbBackend::Sqlite,
            "PRAGMA foreign_keys",
        ))
        .await?
        .ok_or("Missing foreign_keys setting")?;
    assert_eq!(foreign_keys.try_get::<i64>("", "foreign_keys")?, 1);
    let (image_constraint, owner_constraint, token_constraint) = match scenario.relation.as_str() {
        "default" => ("", " REFERENCES user(id) ON DELETE CASCADE", ""),
        "alternate-account-reference" => ("", "", " REFERENCES user(id) ON DELETE CASCADE"),
        "reverse-user-reference-many" => (" REFERENCES account(id) ON DELETE CASCADE", "", ""),
        "unique-account-reference" => ("", " UNIQUE REFERENCES user(id) ON DELETE CASCADE", ""),
        value => return Err(format!("Unknown physical relation: {value}").into()),
    };
    let user = format!(
        r#"CREATE TABLE user (
        id TEXT NOT NULL PRIMARY KEY, name TEXT, email TEXT NOT NULL UNIQUE,
        emailVerified BOOLEAN NOT NULL DEFAULT 0, image TEXT{image_constraint},
        createdAt TIMESTAMP NOT NULL, updatedAt TIMESTAMP NOT NULL
    )"#
    );
    let account = format!(
        r#"CREATE TABLE account (
        id TEXT NOT NULL PRIMARY KEY, accountId TEXT, providerId TEXT NOT NULL,
        userId TEXT{owner_constraint}, accessToken TEXT{token_constraint}, refreshToken TEXT,
        idToken TEXT, accessTokenExpiresAt TIMESTAMP, refreshTokenExpiresAt TIMESTAMP,
        scope TEXT, password TEXT, createdAt TIMESTAMP NOT NULL, updatedAt TIMESTAMP NOT NULL
    )"#
    );
    for sql in [user, account,
        r#"CREATE TABLE session (
            id TEXT NOT NULL PRIMARY KEY, expiresAt TIMESTAMP NOT NULL, token TEXT NOT NULL UNIQUE,
            createdAt TIMESTAMP NOT NULL, updatedAt TIMESTAMP NOT NULL, ipAddress TEXT, userAgent TEXT,
            userId TEXT NOT NULL REFERENCES user(id) ON DELETE CASCADE
        )"#.into(),
        r#"CREATE TABLE verification (
            id TEXT NOT NULL PRIMARY KEY, identifier TEXT NOT NULL, value TEXT NOT NULL,
            expiresAt TIMESTAMP NOT NULL, createdAt TIMESTAMP NOT NULL, updatedAt TIMESTAMP NOT NULL
        )"#.into(),
    ] {
        let _ = database.execute_raw(Statement::from_string(DbBackend::Sqlite, sql)).await?;
    }
    Ok(database)
}

pub(super) async fn seed<S: AuthSchema>(
    store: &dyn AuthStore<S>,
    scenario: &Scenario,
) -> TestResult {
    let date: FieldDate = "2030-01-02T03:04:05Z"
        .parse::<chrono::DateTime<chrono::Utc>>()?
        .into();
    for model in if scenario.many {
        ["account", "user"]
    } else {
        ["user", "account"]
    } {
        if model == "user" {
            for suffix in ["a", "b", "c"] {
                let image = if scenario.many {
                    if suffix == "a" {
                        "account-b".into()
                    } else {
                        "account-a".into()
                    }
                } else {
                    format!("image-{suffix}")
                };
                let _ = store
                    .create_user(CreateUser {
                        id: Some(format!("user-{suffix}")),
                        name: Some(format!("User {suffix}")).into(),
                        email: Some(format!("{suffix}@account-user-auth-boundary.test")),
                        email_verified: Some(true),
                        image: Some(image).into(),
                        created_at: Some(date.clone()),
                        updated_at: Some(date.clone()),
                        ..Default::default()
                    })
                    .await?;
            }
        } else {
            for suffix in ["a", "b"] {
                let account_id = if scenario.accounts_one {
                    format!("user-{suffix}")
                } else if suffix == "a" {
                    "external-owner".into()
                } else {
                    "external-decoy".into()
                };
                let _ = store
                    .create_account(CreateAccount {
                        id: format!("account-{suffix}").into(),
                        account_id: account_id.into(),
                        provider_id: if scenario.accounts_one {
                            "credential"
                        } else {
                            "google"
                        }
                        .into(),
                        user_id: format!("user-{suffix}").into(),
                        access_token: Some(
                            if suffix == "a" { "user-b" } else { "user-a" }.to_owned(),
                        )
                        .into(),
                        refresh_token: None::<String>.into(),
                        id_token: None::<String>.into(),
                        access_token_expires_at: None::<FieldDate>.into(),
                        refresh_token_expires_at: None::<FieldDate>.into(),
                        scope: None::<String>.into(),
                        password: scenario
                            .accounts_one
                            .then(|| PASSWORD_HASH.to_owned())
                            .into(),
                        created_at: date.clone().into(),
                        updated_at: date.clone().into(),
                        ..Default::default()
                    })
                    .await?;
            }
        }
    }
    Ok(())
}

#[derive(Clone, Copy)]
pub(super) enum Backend<'a> {
    Memory(&'a EphemeralStore),
    Sqlite(&'a DatabaseConnection),
}

impl Backend<'_> {
    pub(super) fn is_sqlite(self) -> bool {
        matches!(self, Self::Sqlite(_))
    }

    pub(super) async fn snapshot(self) -> TestResult<Value> {
        match self {
            Self::Sqlite(database) => sqlite_snapshot(database).await,
            Self::Memory(store) => {
                let mut tables = serde_json::Map::new();
                for (name, role) in [
                    ("user", EntityRole::User),
                    ("account", EntityRole::Account),
                    ("session", EntityRole::Session),
                    ("verification", EntityRole::Verification),
                ] {
                    let rows = store
                        .storage_rows(role)?
                        .into_iter()
                        .map(|row| values::observe(&row.into()))
                        .collect::<AuthResult<Vec<_>>>()?;
                    let _ = tables.insert(name.into(), rows.into());
                }
                Ok(tables.into())
            }
        }
    }
}

async fn sqlite_snapshot(database: &DatabaseConnection) -> TestResult<Value> {
    let mut tables = serde_json::Map::new();
    for table in ["user", "account", "session", "verification"] {
        let columns = database
            .query_all_raw(Statement::from_string(
                DbBackend::Sqlite,
                format!("PRAGMA table_info(\"{table}\")"),
            ))
            .await?;
        let names = columns
            .iter()
            .map(|row| row.try_get::<String>("", "name"))
            .collect::<Result<Vec<_>, _>>()?;
        if names.is_empty() {
            let _ = tables.insert(table.into(), Value::Null);
            continue;
        }
        let fields = names
            .iter()
            .map(|name| {
                format!(
                    "'{}', \"{}\"",
                    name.replace('\'', "''"),
                    name.replace('"', "\"\"")
                )
            })
            .collect::<Vec<_>>()
            .join(", ");
        let rows = database
            .query_all_raw(Statement::from_string(
                DbBackend::Sqlite,
                format!("SELECT json_object({fields}) AS data FROM \"{table}\" ORDER BY \"id\""),
            ))
            .await?;
        let mut observed = Vec::new();
        for row in rows {
            let mut record: Value = serde_json::from_str(&row.try_get::<String>("", "data")?)?;
            // Driver timestamp text differs; compare the persisted instants and preserve every other SQLite value.
            for name in [
                "createdAt",
                "updatedAt",
                "expiresAt",
                "accessTokenExpiresAt",
                "refreshTokenExpiresAt",
            ] {
                if let Some(Value::String(value)) = record.get_mut(name) {
                    *value = value
                        .parse::<chrono::DateTime<chrono::Utc>>()?
                        .to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
                }
            }
            observed.push(record);
        }
        let _ = tables.insert(table.into(), Value::Array(observed));
    }
    Ok(Value::Object(tables))
}

pub(super) fn assert_snapshot(
    actual: &Value,
    expected: &Value,
    sqlite: bool,
    case: &impl std::fmt::Debug,
) {
    let backend = if sqlite { "SQLite" } else { "Memory" };
    assert_eq!(actual, expected, "{case:?}: complete {backend} rows");
    if !sqlite {
        let row_keys = |rows: &Value| {
            rows.as_array()
                .map(|rows| rows.iter().map(recorder::object_keys).collect::<Vec<_>>())
        };
        for model in ["user", "account", "session", "verification"] {
            assert_eq!(
                row_keys(&actual[model]),
                row_keys(&expected[model]),
                "{case:?}: Memory {model} row own-property order"
            );
        }
    }
}
