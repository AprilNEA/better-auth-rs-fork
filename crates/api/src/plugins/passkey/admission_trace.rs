use super::*;
use std::{
    future::Future,
    sync::atomic::{AtomicU64, Ordering},
};
use tracing::{
    Event, Metadata, Subscriber, field::Visit, instrument::WithSubscriber,
    level_filters::LevelFilter, span,
};

static NEXT_SPAN: AtomicU64 = AtomicU64::new(0);

#[derive(Default)]
pub(super) struct AdmissionTrace {
    pub events: Mutex<Vec<String>>,
    pub owners: Mutex<Vec<FieldValue>>,
    pub sessions: Mutex<Vec<SessionView>>,
    pub banned_users: Mutex<Vec<FieldMap>>,
}

impl AdmissionTrace {
    pub(super) fn capture<F: Future>(
        self: &Arc<Self>,
        operation: F,
    ) -> impl Future<Output = F::Output> + use<F> {
        operation.with_subscriber(DatabaseSpans(self.clone()))
    }
}

#[better_auth_core::database_hooks()]
impl DatabaseHooks<StatelessSchema> for AdmissionTrace {
    async fn before_create_session(
        &self,
        fields: &mut FieldMap,
        _: &DatabaseHookContext<'_, StatelessSchema>,
    ) -> AuthResult<DatabaseHookUpdate<FieldMap>> {
        self.events.lock().unwrap().push("session:before".into());
        self.owners
            .lock()
            .unwrap()
            .push(fields.get("userId").cloned().unwrap_or_default());
        Ok(DatabaseHookUpdate::Continue)
    }

    async fn after_create_session(
        &self,
        session: Option<&SessionView>,
        _: &DatabaseHookContext<'_, StatelessSchema>,
    ) -> AuthResult<()> {
        let session = session
            .ok_or_else(|| better_auth_core::AuthError::internal("Expected created fixture row"))?;
        self.events.lock().unwrap().push("session:after".into());
        self.sessions.lock().unwrap().push(session.clone());
        Ok(())
    }
}

struct DatabaseSpans(Arc<AdmissionTrace>);
struct SpanFields<'a>(&'a AdmissionTrace);

impl Visit for SpanFields<'_> {
    fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
        if field.name() == "otel.name"
            && matches!(
                value,
                "db findOne passkey"
                    | "db update passkey"
                    | "db findOne user"
                    | "db update user"
                    | "db create session"
            )
        {
            self.0.events.lock().unwrap().push(value.into());
        }
    }

    fn record_debug(&mut self, _: &tracing::field::Field, _: &dyn std::fmt::Debug) {}
}

impl Subscriber for DatabaseSpans {
    fn enabled(&self, _: &Metadata<'_>) -> bool {
        true
    }

    fn max_level_hint(&self) -> Option<LevelFilter> {
        Some(LevelFilter::TRACE)
    }

    fn new_span(&self, attributes: &span::Attributes<'_>) -> span::Id {
        attributes.record(&mut SpanFields(&self.0));
        span::Id::from_u64(NEXT_SPAN.fetch_add(1, Ordering::Relaxed) + 1)
    }

    fn record(&self, _: &span::Id, _: &span::Record<'_>) {}
    fn record_follows_from(&self, _: &span::Id, _: &span::Id) {}
    fn event(&self, _: &Event<'_>) {}
    fn enter(&self, _: &span::Id) {}
    fn exit(&self, _: &span::Id) {}
}

#[tokio::test]
async fn unscoped_first_span_preserves_parallel_capture_isolation() {
    async fn database_operation(model: &str, operation: &str) {
        better_auth_core::observability::database::with_database_operation(
            &test_helpers::create_test_config(),
            model,
            operation,
            async { Ok(()) },
        )
        .await
        .expect("database trace regression operation should succeed");
    }

    let first = Arc::<AdmissionTrace>::default();
    let pending = first.capture(database_operation("session", "create"));
    std::thread::spawn(|| {
        tokio::runtime::Builder::new_current_thread()
            .build()
            .expect("unscoped span runtime should build")
            .block_on(database_operation("user", "findOne"));
    })
    .join()
    .expect("unscoped span thread must complete");
    pending.await;
    assert_eq!(*first.events.lock().unwrap(), ["db create session"]);

    let second = Arc::<AdmissionTrace>::default();
    tokio::join!(
        first.capture(async {
            database_operation("passkey", "findOne").await;
            tokio::task::yield_now().await;
            database_operation("passkey", "update").await;
        }),
        second.capture(async {
            database_operation("user", "findOne").await;
            tokio::task::yield_now().await;
            database_operation("user", "update").await;
        }),
    );
    assert_eq!(
        *first.events.lock().unwrap(),
        [
            "db create session",
            "db findOne passkey",
            "db update passkey"
        ]
    );
    assert_eq!(
        *second.events.lock().unwrap(),
        ["db findOne user", "db update user"]
    );
}
