use super::*;

async fn contract<S: AuthSchema>(raw: Arc<dyn AuthStore<S>>) -> AuthResult<()> {
    let key = seed(raw.as_ref(), "legacy-timestamp").await?;
    let metadata = json!({"legacy":"value"});
    let key = ApiKey::from_field_values(required(
        raw.update_api_key_record(
            &key.id,
            [("metadata".into(), metadata.to_string().into())].into(),
        )
        .await?,
        "Expected the legacy API Key metadata",
    )?)?;
    let auth = BetterAuth::new(config())
        .store_arc(raw.clone())
        .plugin(ApiKeyPlugin::builder().build())
        .build()
        .await?;
    let mut expected_stored = serde_json::to_value(&key)?;
    let mut expected_public = serde_json::to_value(ApiKeyView::try_from_api_key(&key)?)?;
    assert_eq!(expected_stored.get("updatedAt"), Some(&json!(OLD)));
    assert_eq!(
        expected_stored.get("metadata"),
        Some(&json!(metadata.to_string()))
    );
    let updated = auth
        .api_keys()?
        .update(
            "ordinary-owner",
            key.id.typed()?,
            UpdateKeyOptions {
                name: Some("Mobile".into()),
                ..Default::default()
            },
        )
        .await?;
    expected_public["name"] = json!("Mobile");
    expected_public["metadata"] = metadata.clone();
    expected_stored["name"] = json!("Mobile");
    expected_stored["metadata"] = metadata;
    assert_eq!(serde_json::to_value(updated)?, expected_public);
    assert_eq!(stored(raw.as_ref(), &key).await?, expected_stored);
    Ok(())
}

#[tokio::test]
async fn memory_legacy_metadata_repair_preserves_the_timestamp_and_complete_record()
-> AuthResult<()> {
    contract(memory()).await
}

#[tokio::test]
async fn sqlite_legacy_metadata_repair_preserves_the_timestamp_and_complete_record()
-> AuthResult<()> {
    contract(sqlite().await?).await
}
