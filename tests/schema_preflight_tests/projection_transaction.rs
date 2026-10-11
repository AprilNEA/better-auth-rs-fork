use super::*;
use better_auth_core::{
    FieldMap, FieldValue,
    store::schema::{SchemaCheck, SchemaInspector, SchemaValidation},
    user_fields::{FieldTransforms, UserConfig, UserFieldConfig, UserFieldTransform},
};
use serde_json::{Value, json};
use std::{
    sync::{Mutex, OnceLock, Weak},
    time::Duration,
};
use tokio::sync::{Notify, mpsc};

#[tokio::test]
async fn projection_callback_preserves_transaction_schema_scope_for_nested_ok() {
    let mut options = better_auth_seaorm::sea_orm::ConnectOptions::new("sqlite::memory:");
    let _ = options.max_connections(1);
    let mut database = Database::connect(options).await.unwrap();
    migrator::run_migrations(&database).await.unwrap();
    execute(&database, "INSERT INTO users (id, name, email, email_verified, image, created_at, updated_at) VALUES ('owner', 'Owner', 'owner@projection-transaction.test', 1, NULL, '2030-01-01T00:00:00.000Z', '2030-01-01T00:00:00.000Z')").await;
    let queries = Arc::new(AtomicUsize::new(0));
    let count = queries.clone();
    database.set_metric_callback(move |query| {
        if query.statement.sql.contains("sqlite_schema") {
            let _ = count.fetch_add(1, Ordering::SeqCst);
        }
    });
    let auth_handle = Arc::new(OnceLock::<Weak<BetterAuth<BundledSchema>>>::new());
    let responses = Arc::new(Mutex::new(Vec::<(u16, Value)>::new()));
    let callback_auth = auth_handle.clone();
    let callback_responses = responses.clone();
    let mut settings = config();
    let _ = settings.user.fields_mut().insert(
        "name".into(),
        UserFieldConfig {
            transform: Some(FieldTransforms {
                output: Some(UserFieldTransform::new_async(move |value| {
                    let auth = callback_auth.clone();
                    let responses = callback_responses.clone();
                    async move {
                        let auth = auth.get().and_then(Weak::upgrade).ok_or_else(|| {
                            AuthError::internal("Nested schema callback lost its auth instance")
                        })?;
                        let response = auth
                            .call_endpoint(HttpMethod::Get, "/ok", EndpointInput::default())
                            .await?;
                        let body = response.body.bytes()?;
                        responses
                            .lock()
                            .map_err(|_| {
                                AuthError::internal("Nested /ok observation lock poisoned")
                            })?
                            .push((response.status, serde_json::from_slice(body.as_ref())?));
                        Ok(value)
                    }
                })),
                ..Default::default()
            }),
            ..Default::default()
        },
    );
    let store = SeaOrmStore::<BundledSchema>::new(settings.clone(), database);
    let auth = Arc::new(build(store.clone(), settings, Observe(Default::default())).await);
    assert!(auth_handle.set(Arc::downgrade(&auth)).is_ok());
    assert_eq!(http(&auth).await.unwrap().status, 200);
    assert_eq!(queries.load(Ordering::SeqCst), 1);
    let value = tokio::time::timeout(
        Duration::from_secs(5),
        auth.context()
            .database
            .transaction_boxed(Box::new(move |transaction| {
                Box::pin(async move {
                    store.invalidate_schema_check();
                    let user = transaction.get_user_by_id("owner").await?.ok_or_else(|| {
                        AuthError::internal("Transaction fixture User disappeared")
                    })?;
                    Ok(Box::new(user) as better_auth_core::store::BoxedTransactionValue)
                })
            })),
    )
    .await
    .unwrap()
    .unwrap();
    let user = value.downcast::<better_auth_core::UserView>().unwrap();
    assert_eq!(user.name.field_value(), FieldValue::from("Owner"));
    assert_eq!(*responses.lock().unwrap(), vec![(200, json!({"ok":true}))]);
    assert_eq!(queries.load(Ordering::SeqCst), 1);
    assert_eq!(http(&auth).await.unwrap().status, 200);
    assert_eq!(queries.load(Ordering::SeqCst), 2);
}

struct RequiredCheck(Arc<AtomicUsize>);

#[async_trait]
impl SchemaInspector for RequiredCheck {
    async fn findings(&self) -> AuthResult<Vec<SchemaFinding>> {
        let _ = self.0.fetch_add(1, Ordering::SeqCst);
        Ok(vec![SchemaFinding::MissingTable {
            table: "late_validation".into(),
        }])
    }
}

#[tokio::test]
async fn retained_projection_peer_loses_schema_exemption_when_transaction_returns_error() {
    tokio::time::timeout(Duration::from_secs(5), async {
        let checks = Arc::new(AtomicUsize::new(0));
        let validation = SchemaValidation {
            check: Arc::new(SchemaCheck::new(Arc::new(RequiredCheck(checks.clone())))),
            runtime_enabled: true,
        };
        let reject = Arc::new(Notify::new());
        let release = Arc::new(Notify::new());
        let (started, mut starts) = mpsc::unbounded_channel();
        let (finished, mut finishes) = mpsc::unbounded_channel();
        let callback_validation = validation.clone();
        let early_gate = reject.clone();
        let late_gate = release.clone();
        let original = String::from("original-transaction-projection-error");
        let original_pointer = original.as_ptr() as usize;
        let original = Arc::new(Mutex::new(Some(original)));
        let mut fields = UserConfig::default();
        let _ = fields.fields_mut().insert("name".into(), UserFieldConfig {
            transform: Some(FieldTransforms {
                output: Some(UserFieldTransform::new_async(move |value| {
                    let (validation, reject, release, started, finished, original) = (
                        callback_validation.clone(), early_gate.clone(), late_gate.clone(),
                        started.clone(), finished.clone(), original.clone(),
                    );
                    async move {
                        validation.check_runtime().await?;
                        started.send(value.clone()).map_err(|_| AuthError::internal("Projection startup observer closed"))?;
                        if value == FieldValue::from("early") {
                            reject.notified().await;
                            let error = original.lock().map_err(|_| AuthError::internal("Original error lock poisoned"))?
                                .take().ok_or_else(|| AuthError::internal("Original error consumed twice"))?;
                            return Err(AuthError::Config(error));
                        }
                        release.notified().await;
                        finished.send(validation.check_runtime().await)
                            .map_err(|_| AuthError::internal("Late schema observer closed"))?;
                        Ok(value)
                    }
                })),
                ..Default::default()
            }),
            ..Default::default()
        });
        let task = tokio::spawn(async move {
            validation.in_transaction(async move {
                let rows = ["early", "late"].map(|name| FieldMap::from([("name".into(), name.into())]));
                fields.project_records(&rows, true, true).await
            }).await
        });
        assert_eq!(starts.recv().await.unwrap(), FieldValue::from("early"));
        assert_eq!(starts.recv().await.unwrap(), FieldValue::from("late"));
        assert_eq!(checks.load(Ordering::SeqCst), 0);
        reject.notify_one();
        let error = task.await.unwrap().unwrap_err();
        let AuthError::Config(original) = error else { panic!("Projection replaced the original error") };
        assert_eq!(original, "original-transaction-projection-error");
        assert_eq!(original.as_ptr() as usize, original_pointer);
        assert_eq!(checks.load(Ordering::SeqCst), 0);
        release.notify_one();
        let result = finishes.recv().await.unwrap();
        let error = mismatch(result.unwrap_err());
        assert_eq!(checks.load(Ordering::SeqCst), 1);
        assert_eq!(findings(&error), &[SchemaFinding::MissingTable { table: "late_validation".into() }]);
        assert_eq!(error.to_string(), "Database schema mismatch\n\n  Missing tables\n    late_validation\n\n  help: Run `npx auth migrate` to add the missing tables and columns.");
    }).await.unwrap();
}
