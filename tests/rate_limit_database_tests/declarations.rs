use super::{TestResult, adapter_storage_snapshot::Storage};
use async_trait::async_trait;
use better_auth::BetterAuth;
use better_auth_core::{
    AuthConfig, AuthContext, AuthError, AuthInitContext, AuthPlugin, AuthRequest, AuthResponse,
    AuthResult, AuthRoute, AuthSchema, AuthStore, FieldMap, FieldValue,
    id::{IdGeneration, IdGenerator},
    middleware::{EndpointRateLimit, RateLimitConfig, RateLimitStorageKind},
    store::{EphemeralStore, schema::EntityRole},
    user_fields::{FieldTransforms, UserConfig, UserFieldConfig, UserFieldTransform},
};
use better_auth_seaorm::{
    PluginModels, SeaOrmStore,
    sea_orm::{ConnectionTrait, Database, Schema},
    store::{
        __private_test_support::{bundled_schema::BundledSchema, migrator},
        entities,
    },
};
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicUsize, Ordering},
};

#[expect(
    unreachable_pub,
    reason = "SeaORM derives require public fixture entity types"
)]
mod mapped {
    use better_auth_seaorm::sea_orm::{self, entity::prelude::*};

    #[derive(Clone, Debug, PartialEq, DeriveEntityModel, better_auth_seaorm::AuthEntity)]
    #[auth(role = "rate_limit", model_name = "configured_counter")]
    #[sea_orm(table_name = "configured_counter")]
    pub struct Model {
        #[sea_orm(primary_key, auto_increment = false)]
        pub id: String,
        #[sea_orm(column_name = "bucket", unique)]
        pub key: String,
        #[sea_orm(column_name = "hits", column_type = "Integer")]
        pub count: better_auth_seaorm::SqlNumber,
        #[sea_orm(column_name = "touched")]
        pub last_request: i64,
    }

    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}
    impl ActiveModelBehavior for ActiveModel {}
}

type MappedPlugins = PluginModels<
    entities::api_key::Model,
    entities::device_code::Model,
    entities::passkey::Model,
    entities::two_factor::Model,
    entities::jwk::Model,
    entities::wallet_address::Model,
    mapped::Model,
>;

#[derive(Default)]
struct Calls {
    init: Mutex<Vec<&'static str>>,
    callbacks: AtomicUsize,
    ids: AtomicUsize,
}

impl Calls {
    fn transform(self: &Arc<Self>, phase: &'static str) -> UserFieldTransform {
        let calls = self.clone();
        UserFieldTransform::new(move |_| {
            let _ = calls.callbacks.fetch_add(1, Ordering::Relaxed);
            Err(AuthError::internal(format!(
                "Discarded RateLimit {phase} ran"
            )))
        })
    }

    fn declaration(self: &Arc<Self>, name: &str) -> UserFieldConfig {
        let default = self.clone();
        let update = self.clone();
        UserFieldConfig {
            field_name: Some(format!("plugin_{name}")),
            required: Some(false),
            returned: Some(false),
            unique: Some(false),
            default_value_fn: Some(Arc::new(move || {
                let _ = default.callbacks.fetch_add(1, Ordering::Relaxed);
                Err(AuthError::internal("Discarded RateLimit default ran"))
            })),
            on_update: Some(Arc::new(move || {
                let _ = update.callbacks.fetch_add(1, Ordering::Relaxed);
                Err(AuthError::internal("Discarded RateLimit update ran"))
            })),
            transform: Some(FieldTransforms {
                input: Some(self.transform("input")),
                output: Some(self.transform("output")),
            }),
            ..Default::default()
        }
    }
}

struct Declaration {
    last: bool,
    calls: Arc<Calls>,
}

#[async_trait]
impl<S: AuthSchema> AuthPlugin<S> for Declaration {
    fn name(&self) -> &'static str {
        if self.last {
            "rate-limit-last"
        } else {
            "rate-limit-first"
        }
    }
    fn routes(&self) -> Vec<AuthRoute> {
        Vec::new()
    }
    async fn on_init(&self, context: &mut AuthInitContext<S>) -> AuthResult<()> {
        self.calls
            .init
            .lock()
            .map_err(|_| AuthError::internal("RateLimit init lock poisoned"))?
            .push(if self.last { "last" } else { "first" });
        context.register_custom_model(
            if self.last { "after" } else { "before" },
            None,
            UserConfig::default(),
        )?;
        let fields = if self.last {
            UserConfig::default()
        } else {
            UserConfig {
                additional_fields: Some(
                    ["id", "count", "key", "label"]
                        .into_iter()
                        .map(|name| (name.into(), self.calls.declaration(name)))
                        .collect(),
                ),
            }
        };
        context.register_model_schema(
            EntityRole::RateLimit,
            Some(if self.last {
                "plugin_counter"
            } else {
                "first_counter"
            }),
            fields,
        )
    }
    async fn on_request(
        &self,
        _: &AuthRequest,
        _: &AuthContext<S>,
    ) -> AuthResult<Option<AuthResponse>> {
        Ok(None)
    }
}

fn config(calls: &Arc<Calls>) -> AuthConfig {
    let mut config =
        AuthConfig::new("rate-limit-declaration-secret-at-least-thirty-two-characters")
            .base_url("http://rate-limit-declaration.test");
    config.telemetry.enabled = false;
    config.logger.disabled = Some(true);
    let calls = calls.clone();
    config.advanced.database.generate_id =
        Some(IdGeneration::Custom(IdGenerator::new(move |request| {
            if request.model != "rateLimit" {
                return Err(AuthError::internal(
                    "RateLimit must generate IDs with its logical model name",
                ));
            }
            let _ = calls.ids.fetch_add(1, Ordering::Relaxed);
            Ok(Some("counter".into()))
        })));
    config
}

fn rate_limit() -> RateLimitConfig {
    RateLimitConfig::new()
        .enabled(true)
        .storage(RateLimitStorageKind::Database)
}

async fn exercise<S: AuthSchema>(
    store: &dyn AuthStore<S>,
    storage: Storage,
    table: &str,
    names: [&str; 3],
    calls: &Calls,
) -> TestResult {
    let key = "192.0.2.17|/ordinary-counter";
    let tables = [("counter", table, EntityRole::RateLimit)];
    let rule = EndpointRateLimit {
        window: 600.0,
        max_requests: 2.0,
    };
    let expected = |count: i32, last: FieldValue| -> FieldMap {
        [
            ("id".into(), "counter".into()),
            (names[0].into(), key.into()),
            (names[1].into(), count.into()),
            (names[2].into(), last),
        ]
        .into()
    };
    assert_eq!(
        *calls
            .init
            .lock()
            .map_err(|_| AuthError::internal("RateLimit init lock poisoned"))?,
        ["first", "last"]
    );
    for count in [1, 2] {
        let start = chrono::Utc::now().timestamp_millis() as f64;
        let decision = store.consume_rate_limit(key, rule, 600.0).await?;
        let finish = chrono::Utc::now().timestamp_millis() as f64;
        assert!(decision.allowed);
        assert_eq!(decision.retry_after, None);
        let snapshot = storage.snapshot(&tables).await?;
        let rows = snapshot
            .get("counter")
            .ok_or_else(|| AuthError::internal("Missing counter snapshot"))?;
        assert_eq!(rows.len(), 1);
        let last = rows
            .first()
            .and_then(|row| row.get(names[2]))
            .cloned()
            .ok_or_else(|| AuthError::internal("Missing counter timestamp"))?;
        let time = last
            .as_f64()
            .ok_or_else(|| AuthError::internal("Counter timestamp must be numeric"))?;
        assert!((start..=finish).contains(&time));
        assert_eq!(rows, &[expected(count, last)]);
    }
    let before = storage.snapshot(&tables).await?;
    let denied = store.consume_rate_limit(key, rule, 600.0).await?;
    assert!(!denied.allowed);
    assert!(
        denied
            .retry_after
            .is_some_and(|value| value > 0.0 && value <= 600.0)
    );
    assert_eq!(storage.snapshot(&tables).await?, before);
    let start = chrono::Utc::now().timestamp_millis() as f64;
    let reset = store
        .consume_rate_limit(
            key,
            EndpointRateLimit {
                window: 0.0,
                ..rule
            },
            600.0,
        )
        .await?;
    let finish = chrono::Utc::now().timestamp_millis() as f64;
    assert!(reset.allowed);
    assert_eq!(reset.retry_after, None);
    let snapshot = storage.snapshot(&tables).await?;
    let rows = snapshot
        .get("counter")
        .ok_or_else(|| AuthError::internal("Missing reset snapshot"))?;
    assert_eq!(rows.len(), 1);
    let last = rows
        .first()
        .and_then(|row| row.get(names[2]))
        .cloned()
        .ok_or_else(|| AuthError::internal("Missing reset timestamp"))?;
    let time = last
        .as_f64()
        .ok_or_else(|| AuthError::internal("Reset timestamp must be numeric"))?;
    assert!((start..=finish).contains(&time));
    assert_eq!(rows, &[expected(1, last)]);
    assert_eq!(calls.callbacks.load(Ordering::Relaxed), 0);
    assert_eq!(calls.ids.load(Ordering::Relaxed), 1);
    Ok(())
}

#[tokio::test]
async fn memory_counter_consumption_ignores_replaced_plugin_declarations() -> TestResult {
    let calls = Arc::new(Calls::default());
    let config = config(&calls);
    let raw = EphemeralStore::new(Arc::new(config.clone()));
    let auth = BetterAuth::new(config)
        .store(raw.clone())
        .plugin(Declaration {
            last: false,
            calls: calls.clone(),
        })
        .plugin(Declaration {
            last: true,
            calls: calls.clone(),
        })
        .rate_limit(rate_limit())
        .build()
        .await?;
    exercise(
        auth.context().database.as_ref(),
        Storage::Memory(Box::new(raw)),
        "rateLimit",
        ["key", "count", "lastRequest"],
        &calls,
    )
    .await
}

#[tokio::test]
async fn sqlite_counter_consumption_preserves_native_and_mapped_columns_after_replacement()
-> TestResult {
    for custom in [false, true] {
        let calls = Arc::new(Calls::default());
        let config = config(&calls);
        let database = Database::connect("sqlite::memory:").await?;
        migrator::run_migrations(&database).await?;
        let auth = if custom {
            let _ = database
                .execute(
                    &Schema::new(database.get_database_backend())
                        .create_table_from_entity(mapped::Entity),
                )
                .await?;
            BetterAuth::<BundledSchema>::new(config.clone())
                .store(
                    SeaOrmStore::<BundledSchema>::new(config, database.clone())
                        .with_plugin_schema::<MappedPlugins>(),
                )
                .plugin(Declaration {
                    last: false,
                    calls: calls.clone(),
                })
                .plugin(Declaration {
                    last: true,
                    calls: calls.clone(),
                })
                .rate_limit(rate_limit())
                .build()
                .await?
        } else {
            BetterAuth::<BundledSchema>::new(config.clone())
                .store(SeaOrmStore::<BundledSchema>::new(config, database.clone()))
                .plugin(Declaration {
                    last: false,
                    calls: calls.clone(),
                })
                .plugin(Declaration {
                    last: true,
                    calls: calls.clone(),
                })
                .rate_limit(rate_limit())
                .build()
                .await?
        };
        let (table, names) = if custom {
            ("configured_counter", ["bucket", "hits", "touched"])
        } else {
            ("rate_limit", ["key", "count", "last_request"])
        };
        exercise(
            auth.context().database.as_ref(),
            Storage::Sqlite(database.clone()),
            table,
            names,
            &calls,
        )
        .await?;
        drop(auth);
        database.close().await?;
    }
    Ok(())
}
