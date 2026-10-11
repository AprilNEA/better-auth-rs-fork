use super::{Trace, record, take_trace};
use better_auth_core::{
    AuthConfig, AuthError, FieldDate, FieldFunction, FieldMap, FieldValue,
    store::SessionStore,
    user_fields::{FieldTransforms, UserFieldConfig, UserFieldTransform, UserFieldType},
};
use better_auth_seaorm::{
    SeaOrmStore,
    sea_orm::{
        ConnectOptions, ConnectionTrait, Database, DatabaseConnection, EntityTrait, QueryOrder,
        Schema,
    },
    store::{__private_test_support::bundled_schema::BundledSchema, entities::session},
};
use serde_json::json;
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

type TestResult = Result<(), Box<dyn std::error::Error>>;

async fn database() -> Result<DatabaseConnection, Box<dyn std::error::Error>> {
    let mut options = ConnectOptions::new("sqlite::memory:");
    let _ = options.max_connections(1);
    let database = Database::connect(options).await?;
    let _ = database
        .execute(
            &Schema::new(database.get_database_backend()).create_table_from_entity(session::Entity),
        )
        .await?;
    let _ = database.execute_unprepared(
        "INSERT INTO sessions (id, token, user_id, expires_at, created_at, updated_at, ip_address, user_agent, active) \
         VALUES ('selected', 'selected-token', 'owner', '2030-01-01T00:00:00.000Z', '2030-01-01T00:00:00.000Z', '2030-01-01T00:00:00.000Z', 'seed-ip', 'seed-agent', 1), \
         ('expired', 'expired-token', 'owner', '2000-01-01T00:00:00.000Z', '2030-01-01T00:00:00.000Z', '2030-01-01T00:00:00.000Z', 'expired-ip', 'expired-agent', 1), \
         ('retained', 'other-token', 'other', '2030-01-01T00:00:00.000Z', '2030-01-01T00:00:00.000Z', '2030-01-01T00:00:00.000Z', 'other-ip', 'other-agent', 1)",
    ).await?;
    Ok(database)
}

fn config(trace: &Trace) -> AuthConfig {
    let mut config = AuthConfig::default();
    let expiry_trace = trace.clone();
    let _ = config.session.fields_mut().insert(
        "expiresAt".into(),
        UserFieldConfig {
            field_type: UserFieldType::Date,
            transform: Some(FieldTransforms {
                input: Some(UserFieldTransform::new(move |_| {
                    record(&expiry_trace, "expiry-input")?;
                    Ok(FieldDate::from_milliseconds(946_771_200_000.0).into())
                })),
                ..Default::default()
            }),
            ..Default::default()
        },
    );
    let updated_trace = trace.clone();
    let input_trace = trace.clone();
    let _ = config.session.fields_mut().insert(
        "updatedAt".into(),
        UserFieldConfig {
            field_type: UserFieldType::Date,
            on_update: Some(Arc::new(move || {
                record(&updated_trace, "updated-on-update")?;
                Ok(super::date().into())
            })),
            transform: Some(FieldTransforms {
                input: Some(UserFieldTransform::new(move |value| {
                    record(&input_trace, "updated-input")?;
                    Ok(value)
                })),
                ..Default::default()
            }),
            ..Default::default()
        },
    );
    let output_trace = trace.clone();
    let _ = config.session.fields_mut().insert(
        "ipAddress".into(),
        UserFieldConfig {
            transform: Some(FieldTransforms {
                output: Some(UserFieldTransform::new(move |value| {
                    record(&output_trace, "ip-output")?;
                    Ok(value)
                })),
                ..Default::default()
            }),
            ..Default::default()
        },
    );
    config
}

fn callback(trace: &Trace, allocation: &Arc<AtomicUsize>) -> FieldValue {
    let trace = trace.clone();
    let allocation = allocation.clone();
    FieldFunction::contextual(move |_, _| {
        record(&trace, "query")?;
        let message = "session-predicate-error".to_owned();
        allocation.store(message.as_ptr() as usize, Ordering::SeqCst);
        Err(AuthError::Internal(message))
    })
    .into()
}

#[tokio::test]
async fn session_active_reads_keep_query_errors_through_declared_aliases() -> TestResult {
    for array in [false, true] {
        let database = database().await?;
        let before = session::Entity::find()
            .order_by_asc(session::Column::Id)
            .all(&database)
            .await?;
        let trace = Trace::default();
        let allocation = Arc::new(AtomicUsize::new(0));
        let mut config = config(&trace);
        let _ = config.session.fields_mut().insert(
            "expiresAt".into(),
            UserFieldConfig {
                field_type: UserFieldType::Date,
                field_name: Some("updatedAt".into()),
                ..Default::default()
            },
        );
        let store = SeaOrmStore::<BundledSchema>::new(config, database.clone());
        let callback = callback(&trace, &allocation);
        let value = if array {
            vec![callback].into()
        } else {
            callback
        };
        let result = store.get_user_session_snapshots_value(&value, true).await;
        let Err(AuthError::Internal(message)) = result else {
            return Err(AuthError::internal(format!(
                "Expected the original Session predicate error for array={array}: {result:?}"
            ))
            .into());
        };
        assert_eq!(message, "session-predicate-error");
        assert_eq!(message.as_ptr() as usize, allocation.load(Ordering::SeqCst));
        assert_eq!(take_trace(&trace)?, ["query"]);
        assert_eq!(
            session::Entity::find()
                .order_by_asc(session::Column::Id)
                .all(&database)
                .await?,
            before
        );
    }
    Ok(())
}

#[tokio::test]
async fn session_preservation_repeats_query_parsing_after_the_caught_snapshot() -> TestResult {
    for by_token in [false, true] {
        for array in [false, true] {
            let database = database().await?;
            let before = session::Entity::find()
                .order_by_asc(session::Column::Id)
                .all(&database)
                .await?;
            let trace = Trace::default();
            let allocation = Arc::new(AtomicUsize::new(0));
            let store = SeaOrmStore::<BundledSchema>::new(config(&trace), database.clone());
            let callback = callback(&trace, &allocation);
            let value = if array {
                vec![
                    FieldMap::from([("driver-invalid".into(), true.into())]).into(),
                    callback,
                ]
                .into()
            } else {
                callback
            };
            let result = if by_token {
                store.end_session_by_token_value(&value).await
            } else {
                store
                    .delete_user_sessions_optional_value(&value, true)
                    .await
                    .map(drop)
            };
            let Err(AuthError::Internal(message)) = result else {
                return Err(
                    AuthError::internal(format!(
                        "Expected the original Session predicate error for by_token={by_token}, array={array}: {result:?}"
                    )).into(),
                );
            };
            assert_eq!(message, "session-predicate-error");
            assert_eq!(message.as_ptr() as usize, allocation.load(Ordering::SeqCst));
            assert_eq!(
                take_trace(&trace)?,
                [
                    "query",
                    "expiry-input",
                    "updated-on-update",
                    "updated-input",
                    "query"
                ]
            );
            assert_eq!(
                session::Entity::find()
                    .order_by_asc(session::Column::Id)
                    .all(&database)
                    .await?,
                before
            );
        }
    }
    Ok(())
}

#[tokio::test]
async fn session_singleton_eq_keeps_complete_outputs_and_only_preserves_live_matches() -> TestResult
{
    let database = database().await?;
    let before = session::Entity::find()
        .order_by_asc(session::Column::Id)
        .all(&database)
        .await?;
    assert_eq!(before.len(), 3);
    let trace = Trace::default();
    let store = SeaOrmStore::<BundledSchema>::new(config(&trace), database.clone());
    let owner = vec![FieldValue::from("owner")].into();
    let rows = store.get_user_session_snapshots_value(&owner, true).await?;
    let mut values = Vec::new();
    for (row, companion) in rows {
        assert!(companion.is_none());
        values.push(serde_json::Value::Object(FieldMap::from(row).json()?));
    }
    assert_eq!(
        values,
        [json!({
            "id": "selected", "token": "selected-token", "userId": "owner",
            "expiresAt": "2030-01-01T00:00:00.000Z", "createdAt": "2030-01-01T00:00:00.000Z",
            "updatedAt": "2030-01-01T00:00:00.000Z", "ipAddress": "seed-ip", "userAgent": "seed-agent",
        })]
    );
    assert_eq!(take_trace(&trace)?, ["ip-output"]);
    assert_eq!(
        session::Entity::find()
            .order_by_asc(session::Column::Id)
            .all(&database)
            .await?,
        before
    );
    assert_eq!(
        store
            .delete_user_sessions_optional_value(&owner, true)
            .await?,
        Some(1)
    );
    assert_eq!(
        take_trace(&trace)?,
        [
            "ip-output",
            "expiry-input",
            "updated-on-update",
            "updated-input"
        ]
    );
    let mut expected = before;
    let selected = expected
        .iter_mut()
        .find(|row| row.id == "selected")
        .ok_or_else(|| AuthError::internal("Selected Session is missing"))?;
    selected.expires_at = "2000-01-02T00:00:00Z".parse()?;
    selected.updated_at = "2030-01-01T00:00:01Z".parse()?;
    assert_eq!(
        session::Entity::find()
            .order_by_asc(session::Column::Id)
            .all(&database)
            .await?,
        expected
    );
    assert!(
        store
            .get_user_session_snapshots_value(&owner, true)
            .await?
            .is_empty()
    );
    assert_eq!(take_trace(&trace)?, Vec::<&str>::new());
    Ok(())
}
