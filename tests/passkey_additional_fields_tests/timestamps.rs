use super::*;
use better_auth_core::FieldDate;
use std::sync::atomic::{AtomicU8, Ordering};

#[derive(Clone, Default)]
struct Trace {
    events: Events,
    failure: Arc<AtomicU8>,
}

fn date(milliseconds: f64) -> FieldValue {
    FieldDate::from_milliseconds(milliseconds).into()
}

fn iso(milliseconds: f64) -> AuthResult<String> {
    date(milliseconds)
        .json()?
        .and_then(|value| value.as_str().map(str::to_owned))
        .ok_or_else(|| AuthError::internal("Expected the timestamp ISO string"))
}

impl Trace {
    fn emit(&self, phase: &'static str, value: FieldValue) -> AuthResult<()> {
        locked(&self.events)?.push((phase, "updatedAt", value));
        let failure = self.failure.load(Ordering::SeqCst);
        if matches!(
            (phase, failure),
            ("update", 1) | ("input", 2) | ("output", 3)
        ) {
            return Err(AuthError::internal(format!("timestamp-{phase}-stop")));
        }
        Ok(())
    }

    fn field(&self, column: &str) -> UserFieldConfig {
        let default = self.clone();
        let update = self.clone();
        let input = self.clone();
        let output = self.clone();
        UserFieldConfig {
            field_type: UserFieldType::Date,
            field_name: Some(column.into()),
            required: Some(false),
            default_value_fn: Some(better_auth_core::user_fields::UserFieldFactory::new(
                move || {
                    default.emit("default", FieldValue::Undefined)?;
                    Ok(date(1000.0))
                },
            )),
            on_update: Some(better_auth_core::user_fields::UserFieldFactory::new(
                move || {
                    update.emit("update", FieldValue::Undefined)?;
                    Ok(date(2000.0))
                },
            )),
            transform: Some(FieldTransforms {
                input: Some(UserFieldTransform::new(move |value| {
                    input.emit("input", value.clone())?;
                    let time = value
                        .as_date()
                        .ok_or_else(|| AuthError::internal("Expected the declared timestamp"))?;
                    Ok(date(time.milliseconds() + 10.0))
                })),
                output: Some(UserFieldTransform::new(move |value| {
                    output.emit("output", value.clone())?;
                    let time = better_auth_core::query::field_date(&value)?;
                    Ok(iso(time.milliseconds() + 20.0)?.into())
                })),
            }),
            ..Default::default()
        }
    }

    fn take(&self) -> AuthResult<Vec<Event>> {
        Ok(std::mem::take(&mut *locked(&self.events)?))
    }
}

enum Backend {
    Memory(Box<EphemeralStore>),
    Sqlite(DatabaseConnection, PasskeyStorage),
}

impl Backend {
    fn stored_timestamp(&self, milliseconds: f64) -> AuthResult<FieldValue> {
        match self {
            Self::Memory(_) => Ok(date(milliseconds)),
            Self::Sqlite(_, _) => Ok(iso(milliseconds)?.into()),
        }
    }

    fn projected_timestamp(&self, milliseconds: f64) -> AuthResult<FieldValue> {
        match self {
            Self::Memory(_) => Ok(iso(milliseconds)?.into()),
            Self::Sqlite(_, _) => Ok(date(milliseconds)),
        }
    }

    fn columns(&self) -> (&str, &str) {
        match self {
            Self::Memory(_) | Self::Sqlite(_, PasskeyStorage::Legacy) => ("counter", "updatedAt"),
            Self::Sqlite(_, PasskeyStorage::Native) => ("stored_counter", "stored_short_date"),
        }
    }

    fn timestamp_column(&self) -> &str {
        match self {
            Self::Sqlite(_, PasskeyStorage::Legacy) => "updated_at",
            _ => self.columns().1,
        }
    }

    async fn row(&self) -> TestResult<FieldMap> {
        match self {
            Self::Memory(raw) => raw
                .storage_rows(EntityRole::Passkey)?
                .pop()
                .ok_or_else(|| "Expected the complete Memory Passkey row".into()),
            Self::Sqlite(database, mode) => {
                let sql = match mode {
                    PasskeyStorage::Legacy => {
                        "SELECT id, name, counter, updated_at AS timestamp, credential FROM passkeys"
                    }
                    PasskeyStorage::Native => {
                        "SELECT id, name, stored_counter AS counter, stored_short_date AS timestamp FROM ordinary_passkey_fields"
                    }
                };
                let row = database
                    .query_one_raw(Statement::from_string(DbBackend::Sqlite, sql))
                    .await?
                    .ok_or("Expected the complete SQLite Passkey row")?;
                let timestamp: String = row.try_get("", "timestamp")?;
                let (counter, _) = self.columns();
                let mut fields = FieldMap::from([
                    ("id".into(), row.try_get::<String>("", "id")?.into()),
                    ("name".into(), row.try_get::<String>("", "name")?.into()),
                    (counter.into(), row.try_get::<i64>("", "counter")?.into()),
                    (self.timestamp_column().into(), timestamp.into()),
                ]);
                if *mode == PasskeyStorage::Legacy {
                    let _ = fields.insert(
                        "credential".into(),
                        row.try_get::<String>("", "credential")?.into(),
                    );
                }
                Ok(fields)
            }
        }
    }
}

async fn contract<S: AuthSchema>(
    raw: Arc<dyn AuthStore<S>>,
    backend: Backend,
    mode: PasskeyStorage,
) -> TestResult {
    let trace = Trace::default();
    let (counter_column, timestamp_column) = backend.columns();
    let config = Arc::new(config());
    let mut fields = better_auth_core::plugin_runtime::ModelFields::default();
    fields.register_model_fields(
        EntityRole::Passkey,
        UserConfig {
            additional_fields: Some(
                [
                    ("name".into(), UserFieldConfig::default()),
                    (
                        "counter".into(),
                        UserFieldConfig {
                            field_type: UserFieldType::Number,
                            field_name: Some(counter_column.into()),
                            ..Default::default()
                        },
                    ),
                    ("updatedAt".into(), trace.field(timestamp_column)),
                ]
                .into(),
            ),
        },
    )?;
    fields.set_schema_configuration(&SchemaConfiguration {
        config: config.clone(),
        plugins: Vec::new(),
        metadata: Default::default(),
        secondary_storage: false,
        rate_limit: Default::default(),
    });
    let store = raw.with_runtime(config, Vec::new(), fields)?;
    let mut name = "Desk";
    let mut counter = 0_u64;
    let mut credential = "private-create";
    let mut stored_time = 1010.0;
    for stage in [
        "create",
        "name",
        "explicit",
        "auth",
        "factory-error",
        "input-error",
        "output-error",
    ] {
        let before = if stage == "create" {
            None
        } else {
            Some(backend.row().await?)
        };
        trace.failure.store(
            match stage {
                "factory-error" => 1,
                "input-error" => 2,
                "output-error" => 3,
                _ => 0,
            },
            Ordering::SeqCst,
        );
        let result = if stage == "create" {
            store
                .create_passkey(input(name.into(), counter, mode))
                .await
        } else if stage == "name" {
            name = "Renamed";
            store.update_passkey_name(ID, name).await
        } else if stage == "auth" {
            counter = 1;
            credential = "private-auth";
            let update = match mode {
                PasskeyStorage::Native => UpdatePasskeyAuthentication::Native { counter },
                PasskeyStorage::Legacy => UpdatePasskeyAuthentication::Legacy {
                    credential: credential.into(),
                    counter,
                    backed_up: true,
                    device_type: "multiDevice".into(),
                },
            };
            store
                .update_passkey_authentication(&ID.into(), update)
                .await
        } else {
            let additional_fields = match stage {
                "explicit" => [("updatedAt".into(), date(3000.0))].into(),
                "input-error" | "output-error" => [("updatedAt".into(), date(4000.0))].into(),
                _ => FieldMap::new(),
            };
            store
                .update_passkey(
                    &ID.into(),
                    UpdatePasskey {
                        additional_fields,
                        ..Default::default()
                    },
                )
                .await
        };
        let events = trace.take()?;
        let supplied = match stage {
            "create" => 1000.0,
            "explicit" => 3000.0,
            "input-error" | "output-error" => 4000.0,
            _ => 2000.0,
        };
        let mut expected_events = match stage {
            "create" => vec![("default", "updatedAt", FieldValue::Undefined)],
            "name" | "auth" | "factory-error" => {
                vec![("update", "updatedAt", FieldValue::Undefined)]
            }
            _ => Vec::new(),
        };
        if stage != "factory-error" {
            expected_events.push(("input", "updatedAt", date(supplied)));
            if stage != "input-error" {
                expected_events.push((
                    "output",
                    "updatedAt",
                    backend.stored_timestamp(supplied + 10.0)?,
                ));
                stored_time = supplied + 10.0;
            }
        }
        assert_eq!(events, expected_events, "{stage} callback sequence");
        if stage.ends_with("error") {
            let error = result
                .err()
                .ok_or("Expected the original timestamp callback error")?;
            let phase = if stage == "factory-error" {
                "update"
            } else if stage == "input-error" {
                "input"
            } else {
                "output"
            };
            assert!(
                matches!(error, AuthError::Internal(ref message) if message == &format!("timestamp-{phase}-stop")),
                "{stage} preserves the callback error: {error}"
            );
            if stage != "output-error" {
                assert_eq!(Some(backend.row().await?), before, "{stage} has no write");
                continue;
            }
        } else {
            let row = result?;
            let expected = FieldMap::from([
                ("name".into(), name.into()),
                ("counter".into(), counter.into()),
                (
                    "updatedAt".into(),
                    backend.projected_timestamp(stored_time + 20.0)?,
                ),
                ("id".into(), ID.into()),
            ]);
            assert_record(&PasskeyView::from(&row).field_values()?, &expected, stage);
            match &backend {
                Backend::Memory(_) => assert!(
                    row.updated_at.typed().is_err(),
                    "Memory retains the output callback's string"
                ),
                Backend::Sqlite(_, _) => assert_eq!(
                    row.updated_at.typed()?.milliseconds(),
                    stored_time + 20.0,
                    "SQLite converts the callback's ISO string after the output callback"
                ),
            }
        }
        let mut expected_storage = FieldMap::from([
            ("name".into(), name.into()),
            (counter_column.into(), counter.into()),
            (
                backend.timestamp_column().into(),
                backend.stored_timestamp(stored_time)?,
            ),
            ("id".into(), ID.into()),
        ]);
        if mode == PasskeyStorage::Legacy {
            let _ = expected_storage.insert("credential".into(), credential.into());
        }
        assert_eq!(
            backend.row().await?,
            expected_storage,
            "{stage} complete storage"
        );
    }
    if let Backend::Sqlite(database, _) = backend {
        database.close().await?;
    }
    Ok(())
}

#[tokio::test]
async fn memory_passkey_declared_timestamps_keep_factories_explicit_values_and_errors() -> TestResult
{
    for mode in [PasskeyStorage::Legacy, PasskeyStorage::Native] {
        let raw = EphemeralStore::new(Arc::new(config())).with_passkey_storage(mode);
        contract(Arc::new(raw.clone()), Backend::Memory(Box::new(raw)), mode).await?;
    }
    Ok(())
}

#[tokio::test]
async fn sqlite_passkey_declared_timestamps_keep_factories_explicit_values_and_errors() -> TestResult
{
    for mode in [PasskeyStorage::Legacy, PasskeyStorage::Native] {
        let database = Database::connect("sqlite::memory:").await?;
        let store = SeaOrmStore::<BundledSchema>::new(config(), database.clone());
        let backend = Backend::Sqlite(database.clone(), mode);
        match mode {
            PasskeyStorage::Legacy => {
                let _ = database.execute_unprepared("CREATE TABLE passkeys (id TEXT PRIMARY KEY NOT NULL, name TEXT, counter INTEGER, updated_at TIMESTAMP, credential TEXT)").await?;
                contract(Arc::new(store), backend, mode).await?;
            }
            PasskeyStorage::Native => {
                let _ = database.execute_unprepared("CREATE TABLE ordinary_passkey_fields (id TEXT PRIMARY KEY NOT NULL, name TEXT, stored_counter INTEGER, stored_short_date TIMESTAMP)").await?;
                contract(
                    Arc::new(store.with_plugin_schema::<fixture::Plugins>()),
                    backend,
                    mode,
                )
                .await?;
            }
        }
    }
    Ok(())
}
