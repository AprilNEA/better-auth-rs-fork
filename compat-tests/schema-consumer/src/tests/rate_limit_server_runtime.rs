use super::super::server_catalog_support::TestResult;
use super::{RuntimeCase, quote};
use better_auth::seaorm::{
    __private_chrono as chrono, Database, DatabaseConnection, SeaOrmPluginModel,
    SeaOrmPluginSchema, SeaOrmStore,
    sea_orm::{ConnectOptions, ConnectionTrait, DbBackend, EntityName, Iden, Statement},
};
use better_auth::{
    AuthConfig, AuthSchema,
    middleware::{EndpointRateLimit, RateLimitDecision},
    store::RateLimitStore,
};
use std::sync::Arc;
use tokio::{sync::Barrier, task::JoinSet};

const WINDOW: f64 = 600.0;
const MAXIMUM: i32 = 7;
const WORKERS: usize = 8;

#[derive(Debug, PartialEq)]
struct Snapshot {
    id: String,
    key: String,
    count: i32,
    last_request: i64,
}

struct Call {
    decision: RateLimitDecision,
    started: i64,
    finished: i64,
}

struct Counter {
    backend: DbBackend,
    table: String,
    key: String,
    count: String,
    last_request: String,
}

impl Counter {
    fn new<P: SeaOrmPluginSchema>(backend: DbBackend) -> TestResult<Self> {
        Ok(Self {
            backend,
            table: quote(
                backend,
                <P::RateLimit as SeaOrmPluginModel>::Entity::default().table_name(),
            ),
            key: P::RateLimit::column("key")?.to_string(),
            count: P::RateLimit::column("count")?.to_string(),
            last_request: P::RateLimit::column("last_request")?.to_string(),
        })
    }

    fn parameter(&self, index: usize) -> String {
        if self.backend == DbBackend::Postgres {
            format!("${index}")
        } else {
            "?".into()
        }
    }

    async fn rows(&self, database: &DatabaseConnection, key: &str) -> TestResult<Vec<Snapshot>> {
        let rows = database
            .query_all_raw(Statement::from_sql_and_values(
                self.backend,
                format!(
                    "SELECT * FROM {} WHERE {} = {}",
                    self.table,
                    quote(self.backend, &self.key),
                    self.parameter(1)
                ),
                [key.into()],
            ))
            .await?;
        rows.into_iter()
            .map(|row| {
                assert_eq!(
                    row.column_names(),
                    ["id", &self.key, &self.count, &self.last_request]
                );
                Ok(Snapshot {
                    id: row.try_get("", "id")?,
                    key: row.try_get("", &self.key)?,
                    count: row.try_get("", &self.count)?,
                    last_request: row.try_get("", &self.last_request)?,
                })
            })
            .collect()
    }

    async fn snapshot(
        &self,
        database: &DatabaseConnection,
        key: &str,
        count: i32,
        previous_id: Option<&str>,
        interval: Option<(i64, i64)>,
    ) -> TestResult<Snapshot> {
        let mut rows = self.rows(database, key).await?;
        assert_eq!(rows.len(), 1);
        let row = rows.pop().ok_or("Missing RateLimit business row")?;
        assert!(!row.id.is_empty());
        if let Some(id) = previous_id {
            assert_eq!(row.id, id);
        }
        assert_eq!(row.key, key);
        assert_eq!(row.count, count);
        if let Some((started, finished)) = interval {
            assert!(started <= row.last_request && row.last_request <= finished);
        }
        Ok(row)
    }

    async fn expire(&self, database: &DatabaseConnection, keys: [&str; 2]) -> TestResult {
        let result = database
            .execute_raw(Statement::from_sql_and_values(
                self.backend,
                format!(
                    "UPDATE {} SET {} = 0 WHERE {} IN ({}, {})",
                    self.table,
                    quote(self.backend, &self.last_request),
                    quote(self.backend, &self.key),
                    self.parameter(1),
                    self.parameter(2)
                ),
                keys.map(Into::into),
            ))
            .await?;
        assert_eq!(result.rows_affected(), 2);
        Ok(())
    }

    fn check_retry(&self, call: &Call, row: &Snapshot) -> TestResult {
        assert!(!call.decision.allowed);
        let retry = call
            .decision
            .retry_after
            .ok_or("Missing rejected counter retryAfter")?;
        // SQLx reads i64, but upstream pg exposes decimal text before JavaScript addition.
        let expires = match self.backend {
            DbBackend::Postgres => format!("{}600000", row.last_request).parse::<f64>()?,
            DbBackend::MySql => row.last_request as f64 + WINDOW * 1000.0,
            _ => {
                return Err(
                    "RateLimit server business contracts require PostgreSQL or MySQL".into(),
                );
            }
        };
        let minimum = ((expires - call.finished as f64) / 1000.0).ceil();
        let maximum = ((expires - call.started as f64) / 1000.0).ceil();
        assert_eq!(retry.fract(), 0.0);
        assert!(
            retry >= minimum && retry <= maximum,
            "retryAfter {retry} is outside [{minimum}, {maximum}]"
        );
        Ok(())
    }
}

fn key(label: &str) -> String {
    format!("192.0.2.10|/ordinary-business-{label}")
}

async fn consume(store: &impl RateLimitStore, key: &str) -> TestResult<Call> {
    let started = chrono::Utc::now().timestamp_millis();
    let decision = store
        .consume_rate_limit(
            key,
            EndpointRateLimit {
                window: WINDOW,
                max_requests: f64::from(MAXIMUM),
            },
            WINDOW,
        )
        .await?;
    let finished = chrono::Utc::now().timestamp_millis();
    assert!(started <= finished);
    if decision.allowed {
        assert_eq!(decision.retry_after, None);
    }
    Ok(Call {
        decision,
        started,
        finished,
    })
}

async fn connections(database: &DatabaseConnection) -> TestResult<Vec<DatabaseConnection>> {
    let backend = database.get_database_backend();
    let (variable, sql) = match backend {
        DbBackend::Postgres => (
            "BETTER_AUTH_TEST_POSTGRES_URL",
            "SELECT current_schema() AS namespace",
        ),
        DbBackend::MySql => (
            "BETTER_AUTH_TEST_MYSQL_URL",
            "SELECT DATABASE() AS namespace",
        ),
        _ => return Err("RateLimit server connections require PostgreSQL or MySQL".into()),
    };
    let namespace: String = database
        .query_one_raw(Statement::from_string(backend, sql))
        .await?
        .ok_or("Missing RateLimit test namespace")?
        .try_get("", "namespace")?;
    let mut connections = Vec::with_capacity(WORKERS);
    for _ in 0..WORKERS {
        let mut options = ConnectOptions::new(std::env::var(variable)?);
        let _ = options
            .max_connections(1)
            .min_connections(1)
            .sqlx_logging(false);
        if backend == DbBackend::Postgres {
            let _ = options.set_schema_search_path(namespace.clone());
        } else {
            let namespace = namespace.clone();
            let _ = options.map_sqlx_mysql_opts(move |options| options.database(&namespace));
        }
        let connection = Database::connect(options).await?;
        let observed: String = connection
            .query_one_raw(Statement::from_string(backend, sql))
            .await?
            .ok_or("Missing worker namespace")?
            .try_get("", "namespace")?;
        assert_eq!(observed, namespace);
        connections.push(connection);
    }
    Ok(connections)
}

async fn competing<S: AuthSchema, P: SeaOrmPluginSchema>(
    database: &DatabaseConnection,
    counter: &Counter,
    label: &str,
    initial: i32,
) -> TestResult {
    let key = key(label);
    let store =
        SeaOrmStore::<S>::new(AuthConfig::default(), database.clone()).with_plugin_schema::<P>();
    let existing = if initial == 1 {
        let call = consume(&store, &key).await?;
        assert!(call.decision.allowed);
        Some(
            counter
                .snapshot(
                    database,
                    &key,
                    initial,
                    None,
                    Some((call.started, call.finished)),
                )
                .await?,
        )
    } else {
        assert!(counter.rows(database, &key).await?.is_empty());
        None
    };
    let connections = connections(database).await?;
    let gate = Arc::new(Barrier::new(WORKERS));
    let mut tasks = JoinSet::new();
    for connection in connections {
        let gate = gate.clone();
        let key = key.clone();
        let _ = tasks.spawn(async move {
            let worker = SeaOrmStore::<S>::new(AuthConfig::default(), connection.clone())
                .with_plugin_schema::<P>();
            let _ = gate.wait().await;
            let result = consume(&worker, &key).await;
            drop(worker);
            connection.close().await?;
            result
        });
    }
    let mut results = Vec::with_capacity(WORKERS);
    while let Some(result) = tasks.join_next().await {
        results.push(result??);
    }
    assert_eq!(results.len(), WORKERS);
    let allowed = results
        .iter()
        .filter(|result| result.decision.allowed)
        .count();
    assert_eq!(allowed, (MAXIMUM - initial) as usize);
    assert_eq!(
        results.len() - allowed,
        WORKERS - (MAXIMUM - initial) as usize
    );
    let started = results
        .iter()
        .map(|result| result.started)
        .min()
        .ok_or("Missing concurrent start")?;
    let finished = results
        .iter()
        .map(|result| result.finished)
        .max()
        .ok_or("Missing concurrent finish")?;
    let row = counter
        .snapshot(
            database,
            &key,
            MAXIMUM,
            existing.as_ref().map(|row| row.id.as_str()),
            Some((started, finished)),
        )
        .await?;
    for result in &results {
        if !result.decision.allowed {
            counter.check_retry(result, &row)?;
        }
    }
    counter.check_retry(&consume(&store, &key).await?, &row)?;
    assert_eq!(
        counter
            .snapshot(database, &key, MAXIMUM, None, None)
            .await?,
        row
    );
    Ok(())
}

pub(super) async fn check<S: AuthSchema, P: SeaOrmPluginSchema>(
    database: &DatabaseConnection,
    case: &RuntimeCase,
) -> TestResult {
    let counter = Counter::new::<P>(database.get_database_backend())?;
    let store =
        SeaOrmStore::<S>::new(AuthConfig::default(), database.clone()).with_plugin_schema::<P>();
    let sequential = key("sequential");
    let mut before: Option<Snapshot> = None;
    for count in 1..=MAXIMUM {
        let call = consume(&store, &sequential).await?;
        assert!(
            call.decision.allowed,
            "{} sequential count {count}",
            case.name
        );
        before = Some(
            counter
                .snapshot(
                    database,
                    &sequential,
                    count,
                    before.as_ref().map(|row| row.id.as_str()),
                    Some((call.started, call.finished)),
                )
                .await?,
        );
    }
    let before = before.ok_or("Missing full counter")?;
    counter.check_retry(&consume(&store, &sequential).await?, &before)?;
    assert_eq!(
        counter
            .snapshot(database, &sequential, MAXIMUM, None, None)
            .await?,
        before
    );

    let stale = key("stale");
    assert!(consume(&store, &stale).await?.decision.allowed);
    counter.expire(database, [&sequential, &stale]).await?;
    assert_eq!(
        counter
            .snapshot(database, &sequential, MAXIMUM, None, None)
            .await?
            .last_request,
        0
    );
    assert_eq!(
        counter
            .snapshot(database, &stale, 1, None, None)
            .await?
            .last_request,
        0
    );
    let reset = consume(&store, &sequential).await?;
    assert!(reset.decision.allowed);
    let _ = counter
        .snapshot(
            database,
            &sequential,
            1,
            Some(&before.id),
            Some((reset.started, reset.finished)),
        )
        .await?;
    assert!(counter.rows(database, &stale).await?.is_empty());

    competing::<S, P>(database, &counter, "concurrent-create", 0).await?;
    competing::<S, P>(database, &counter, "concurrent-increment", 1).await?;
    Ok(())
}
