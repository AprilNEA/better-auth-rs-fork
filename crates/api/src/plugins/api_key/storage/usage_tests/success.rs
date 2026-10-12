#![expect(
    clippy::indexing_slicing,
    reason = "The frozen contract validates the two retained task slots before comparing each complete native result."
)]

use super::*;
use better_auth_core::AuthRecordFields;

async fn completion(task: BackgroundTask) -> AuthResult<FieldValue> {
    tokio::time::timeout(Duration::from_secs(5), task)
        .await
        .map_err(|_| AuthError::internal("Successful usage task did not settle"))?
        .map_err(|error| AuthError::internal(format!("Unexpected usage task failure: {error}")))?
}

fn states(values: &[Option<FieldValue>]) -> AuthResult<Value> {
    values
        .iter()
        .map(|value| match value {
            Some(value) => Ok(
                json!({"status":"fulfilled","value":NativeObservation::default().observe(value)?}),
            ),
            None => Ok(json!({"status":"pending"})),
        })
        .collect::<AuthResult<Vec<_>>>()
        .map(Into::into)
}

fn expected_snapshot(source: &Value) -> AuthResult<Value> {
    let mut snapshot = source.clone();
    let task_states = snapshot["taskStates"]
        .as_array_mut()
        .ok_or_else(|| AuthError::internal("Source usage task states missing"))?;
    for state in task_states {
        if let Some(value) = state.get_mut("value") {
            *value = source_value(value)?;
        }
    }
    snapshot["storageEvents"] = source_value(&snapshot["storageEvents"])?;
    snapshot["database"] = source_value(&snapshot["database"])?;
    Ok(snapshot)
}

fn snapshot(
    cache: &Cache,
    store: &EphemeralStore,
    values: &[Option<FieldValue>],
) -> AuthResult<Value> {
    let tables = [
        ("user", EntityRole::User),
        ("session", EntityRole::Session),
        ("account", EntityRole::Account),
        ("verification", EntityRole::Verification),
        ("apikey", EntityRole::ApiKey),
    ]
    .into_iter()
    .map(|(name, role)| {
        Ok((
            name.into(),
            store
                .storage_rows(role)?
                .into_iter()
                .map(FieldValue::from)
                .collect::<Vec<_>>()
                .into(),
        ))
    })
    .collect::<AuthResult<FieldMap>>()?;
    Ok(
        json!({"taskStates":states(values)?,"storageEvents":*lock(&cache.events)?,
        "cacheEntries":cache.entries()?,"database":NativeObservation::default().observe(&tables.into())?}),
    )
}

async fn run(case: &Value) -> AuthResult<()> {
    let name = case["name"]
        .as_str()
        .ok_or_else(|| AuthError::internal("Source usage name missing"))?;
    let pending = case["timing"] == "pending";
    assert_replay(&seed(), &case["original"], name);
    let cache = Arc::new(Cache::successful(pending, &case["fresh"])?);
    assert_replay(&cache.entries()?, &case["before"], name);
    let state = Arc::new(Observation::default());
    let config = Arc::new(state.config());
    let store = Arc::new(EphemeralStore::from_storage(
        config.clone(),
        ["user", "session", "account", "verification", "apikey"]
            .map(|name| (name.into(), Vec::new())),
    )?);
    let clock = chrono::DateTime::from_timestamp_millis(2_000_000_000_000)
        .ok_or_else(|| AuthError::internal("Source clock must be representable"))?;
    let context = AuthContext::new(config, store.clone())?.with_clock(move || clock);
    let plugin = ApiKeyPlugin::with_config(ApiKeyConfig {
        storage: ApiKeyStorage::SecondaryStorage,
        custom_storage: Some(cache.clone()),
        disable_key_hashing: true,
        defer_updates: true,
        ..Default::default()
    });
    let input = VerifyApiKey {
        key: "usage-secret",
        config_id: None,
        permissions: None,
    };
    let mut verification = Box::pin(plugin.verify_api_key(&input, &context));
    let first = std::future::poll_fn(|cx| Poll::Ready(verification.as_mut().poll(cx))).await;
    tokio::time::timeout(Duration::from_secs(5), cache.started.notified())
        .await
        .map_err(|_| AuthError::internal("Successful verification did not reread the key"))?;
    let key = match first {
        Poll::Ready(result) => result,
        Poll::Pending => tokio::time::timeout(Duration::from_secs(5), verification)
            .await
            .map_err(|_| {
                AuthError::internal("Verification waited for the deferred successful reread")
            })?,
    }
    .map_err(|error| AuthError::internal(error.to_string()))?;
    let public: FieldValue = FieldMap::from([
        ("valid".into(), true.into()),
        ("error".into(), FieldValue::Null),
        ("key".into(), key.field_values()?.into()),
    ])
    .into();
    assert_replay(
        &NativeObservation::default().observe(&public)?,
        &source_value(&case["result"])?,
        name,
    );
    let tasks = std::mem::take(&mut *lock(&state.tasks)?);
    assert_eq!(tasks.len(), 2);
    let mut tasks = tasks.into_iter().map(Some).collect::<Vec<_>>();
    let mut values = vec![None, None];
    for (index, task) in tasks.iter_mut().enumerate() {
        if pending && index == 0 {
            continue;
        }
        let task = task
            .take()
            .ok_or_else(|| AuthError::internal("Retained usage task is missing"))?;
        values[index] = Some(completion(task).await?);
    }
    if pending {
        let task = tasks
            .first_mut()
            .and_then(Option::as_mut)
            .ok_or_else(|| AuthError::internal("Pending usage task is missing"))?;
        assert!(
            std::future::poll_fn(|cx| Poll::Ready(std::pin::Pin::new(&mut *task).poll(cx)))
                .await
                .is_pending()
        );
    }
    assert_replay(
        &snapshot(&cache, &store, &values)?,
        &expected_snapshot(&case["beforeRelease"])?,
        name,
    );
    cache.release.notify_one();
    for (index, task) in tasks.into_iter().enumerate() {
        if let Some(task) = task {
            values[index] = Some(completion(task).await?);
        }
    }
    let merged = values
        .first()
        .and_then(Option::as_ref)
        .ok_or_else(|| AuthError::internal("Usage completion must contain the merged record"))?;
    let last_request = merged.model_property("lastRequest")?;
    let updated_at = merged.model_property("updatedAt")?;
    assert!(!last_request.strict_equals(&updated_at));
    assert_eq!(
        better_auth_core::query::field_date(&last_request)?.milliseconds(),
        better_auth_core::query::field_date(&updated_at)?.milliseconds()
    );
    assert!(last_request.strict_equals(&key.last_request.field_value()));
    assert!(updated_at.strict_equals(&key.updated_at.field_value()));
    assert!(
        !merged
            .model_property("createdAt")?
            .strict_equals(&key.created_at.field_value())
    );
    assert_replay(
        &snapshot(&cache, &store, &values)?,
        &expected_snapshot(&case["afterSettlement"])?,
        name,
    );
    assert!(lock(&state.logs)?.is_empty());
    assert_replay(&json!([]), &case["logs"], name);
    assert_replay(&json!([]), &case["functions"], name);
    Ok(())
}

#[tokio::test]
async fn deferred_success_retains_the_complete_fresh_record_and_storage_writes() -> AuthResult<()> {
    let fixture: Value = serde_json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../tests/fixtures/api-key-usage-success-1.7.6.json"
    )))?;
    assert_eq!(fixture["version"], "1.7.6");
    let cases = fixture["cases"]
        .as_array()
        .ok_or_else(|| AuthError::internal("Source usage cases missing"))?;
    assert_eq!(cases.len(), 2);
    for case in cases {
        run(case).await?;
    }
    Ok(())
}
