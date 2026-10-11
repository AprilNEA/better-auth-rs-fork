use super::*;
use better_auth::plugins::api_key::{ApiKeyConfig, ApiKeyStorage};
use better_auth_core::store::{MemoryCacheAdapter, SecondaryStorage};

async fn contract<S: AuthSchema>(raw: Arc<dyn AuthStore<S>>) -> AuthResult<()> {
    let key = seed(raw.as_ref(), "secondary-timestamp").await?;
    let before = serde_json::to_value(&key)?;
    let cache = Arc::new(MemoryCacheAdapter::new());
    let cache_key = format!("api-key:by-id:{}", key.id.typed()?);
    cache.set(&cache_key, &before.to_string(), None).await?;
    let events = Arc::new(Mutex::new(Vec::new()));
    let auth = BetterAuth::new(config())
        .store_arc(raw.clone())
        .plugin(ApiKeyPlugin::with_config(ApiKeyConfig {
            storage: ApiKeyStorage::SecondaryStorage,
            custom_storage: Some(cache.clone()),
            defer_updates: false,
            ..Default::default()
        }))
        .plugin(Fields(vec![(
            EntityRole::ApiKey,
            fields(
                "updatedAt",
                timestamp_policy(events.clone(), Arc::new(AtomicU8::new(1)), true),
            ),
        )]))
        .build()
        .await?;
    let earliest = chrono::Utc::now().timestamp_millis();
    let updated = auth
        .api_keys()?
        .update(
            "ordinary-owner",
            key.id.typed()?,
            UpdateKeyOptions {
                name: Some("Cached".into()),
                ..Default::default()
            },
        )
        .await?;
    let latest = chrono::Utc::now().timestamp_millis();
    let actual = serde_json::to_value(&updated)?;
    let timestamp = updated.updated_at.typed()?.milliseconds();
    assert!((earliest as f64..=latest as f64).contains(&timestamp));
    assert_ne!(actual.get("updatedAt"), Some(&json!(OLD)));
    let mut expected = serde_json::to_value(ApiKeyView::try_from_api_key(&key)?)?;
    expected["name"] = json!("Cached");
    expected["updatedAt"] = actual["updatedAt"].clone();
    assert_eq!(actual, expected);
    let mut expected_cache = before.clone();
    expected_cache["name"] = json!("Cached");
    expected_cache["updatedAt"] = actual["updatedAt"].clone();
    let cached = required(
        cache.get(&cache_key).await?,
        "Expected the updated cache record",
    )?;
    let cached = required(cached.as_str(), "Expected serialized cache JSON")?;
    assert_eq!(serde_json::from_str::<Value>(cached)?, expected_cache);
    assert_eq!(stored(raw.as_ref(), &key).await?, before);
    assert!(trace_lock(&events)?.is_empty());
    Ok(())
}

#[tokio::test]
async fn memory_secondary_updates_own_the_timestamp_and_bypass_adapter_policies() -> AuthResult<()>
{
    contract(memory()).await
}

#[tokio::test]
async fn sqlite_secondary_updates_own_the_timestamp_and_bypass_adapter_policies() -> AuthResult<()>
{
    contract(sqlite().await?).await
}
