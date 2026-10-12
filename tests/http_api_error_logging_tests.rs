//! Paired with contracts/http-api-error-logging.test.ts; facade tests preserve the Rust helper boundary.

use std::sync::{Arc, Mutex, MutexGuard, OnceLock, Weak};

use async_trait::async_trait;
use better_auth::{AuthBuilder, AuthConfig, BetterAuth};
use better_auth_core::{
    AuthContext, AuthError, AuthPlugin, AuthRequest, AuthResponse, AuthResult, AuthRoute, FieldMap,
    FieldValue, HttpMethod,
    observability::{LogArgument, LogLevel, LogSink, logger},
    store::{EphemeralStore, StatelessSchema as S, schema::EntityRole},
};
use serde_json::{Value, json};

#[path = "http_api_error_logging_tests/capture.rs"]
mod capture;
#[path = "http_api_error_logging_tests/facade.rs"]
mod facade;
#[path = "http_api_error_logging_tests/http.rs"]
mod http;

const ORIGIN_A: &str = "https://http-api-error-a.test";
const ORIGIN_B: &str = "https://http-api-error-b.test";
const MESSAGE: &str = "Scoped API failure";

fn lock<T>(value: &Mutex<T>) -> AuthResult<MutexGuard<'_, T>> {
    value
        .lock()
        .map_err(|_| AuthError::internal("Logger contract observation lock poisoned"))
}

fn config(origin: &str) -> AuthConfig {
    let mut config =
        AuthConfig::new("http-api-error-logging-secret-at-least-thirty-two-characters")
            .base_url(origin);
    config.telemetry.enabled = false;
    config.logger.disable_colors = Some(true);
    config
}

fn builder(config: AuthConfig) -> AuthResult<(AuthBuilder<S>, Arc<EphemeralStore>)> {
    let store = store(&config)?;
    let builder = AuthBuilder::new(config)
        .store_arc(store.clone())
        .rate_limit(better_auth_core::middleware::RateLimitConfig {
            enabled: Some(false),
            ..Default::default()
        });
    Ok((builder, store))
}

fn store(config: &AuthConfig) -> AuthResult<Arc<EphemeralStore>> {
    Ok(Arc::new(EphemeralStore::from_storage(
        Arc::new(config.clone()),
        ["user", "session", "account", "verification"].map(|name| (name.into(), Vec::new())),
    )?))
}

fn snapshot(store: &EphemeralStore) -> AuthResult<Value> {
    let mut result = serde_json::Map::new();
    for (name, role) in [
        ("user", EntityRole::User),
        ("session", EntityRole::Session),
        ("account", EntityRole::Account),
        ("verification", EntityRole::Verification),
    ] {
        let rows = FieldValue::from(
            store
                .storage_rows(role)?
                .into_iter()
                .map(FieldValue::from)
                .collect::<Vec<_>>(),
        );
        let _ = result.insert(
            name.into(),
            rows.json()?
                .ok_or_else(|| AuthError::internal("Table array must serialize"))?,
        );
    }
    Ok(result.into())
}

fn request(origin: &str, path: &str) -> AuthResult<AuthRequest> {
    Ok(
        AuthRequest::new(HttpMethod::Get, format!("/api/auth{path}")).with_url(
            format!("{origin}/api/auth{path}")
                .parse()
                .map_err(|error| AuthError::internal(format!("Invalid fixture URL: {error}")))?,
        ),
    )
}

fn response_snapshot(response: &AuthResponse) -> AuthResult<Value> {
    // Fetch Headers iteration sorts names; preserve every pair and all cookie values.
    let mut headers = response.headers.iter().collect::<Vec<_>>();
    headers.sort_by(|left, right| left.0.cmp(right.0));
    Ok(json!({
        "status": response.status,
        "statusText": response.status_text.to_string(),
        "headers": headers,
        "cookies": response.headers.get_all("set-cookie").collect::<Vec<_>>(),
        "body": String::from_utf8(response.body.bytes()?.to_vec())
            .map_err(|error| AuthError::internal(error.to_string()))?,
    }))
}

#[derive(Clone, Debug, PartialEq)]
enum Event {
    Phase(&'static str, &'static str),
    Log {
        sink: &'static str,
        scope: &'static str,
        level: LogLevel,
        message: FieldValue,
        arguments: Vec<FieldValue>,
    },
    Default {
        scope: &'static str,
        fields: Vec<(String, String)>,
    },
    Response(Value),
}

#[derive(Default)]
struct Observations {
    events: Mutex<Vec<Event>>,
    a: OnceLock<Weak<dyn LogSink>>,
    b: OnceLock<Weak<dyn LogSink>>,
    inner_response: Mutex<Option<Value>>,
}

impl Observations {
    fn owner(&self) -> &'static str {
        let current = logger::current();
        let Some(current) = current.log else {
            return "none";
        };
        for (name, sink) in [("A", &self.a), ("B", &self.b)] {
            if sink
                .get()
                .and_then(Weak::upgrade)
                .is_some_and(|sink| Arc::ptr_eq(&current, &sink))
            {
                return name;
            }
        }
        "unexpected"
    }

    fn phase(&self, phase: &'static str) -> AuthResult<()> {
        lock(&self.events)?.push(Event::Phase(phase, self.owner()));
        Ok(())
    }

    fn sink(self: &Arc<Self>, name: &'static str) -> AuthResult<Arc<dyn LogSink>> {
        let sink: Arc<dyn LogSink> = Arc::new(capture::Instance {
            name,
            observations: self.clone(),
        });
        let slot = if name == "A" { &self.a } else { &self.b };
        slot.set(Arc::downgrade(&sink))
            .map_err(|_| AuthError::internal("Logger contract sink already bound"))?;
        Ok(sink)
    }
}
