use super::*;
use better_auth::server_api::UpdateKeyOptions;
use better_auth_core::{ApiKey, ApiKeyView, FromFieldMap};
use std::sync::atomic::{AtomicU8, Ordering};

#[path = "api_key_update_secondary.rs"]
mod secondary;

#[path = "api_key_update_metadata.rs"]
mod metadata;

const OLD: &str = "2000-01-02T03:04:05.000Z";
const GENERATED: &str = "2001-01-02T03:04:05.000Z";
const STORED: &str = "2002-01-02T03:04:05.000Z";
const PROJECTED: &str = "2003-01-02T03:04:05.000Z";
const SUPPLIED: &str = "2004-01-02T03:04:05.000Z";
const USAGE: &str = "2005-01-02T03:04:05.000Z";

fn date(value: &str) -> AuthResult<chrono::DateTime<chrono::Utc>> {
    value
        .parse()
        .map_err(|error| AuthError::internal(format!("Invalid timestamp fixture: {error}")))
}

fn event(phase: &str, value: &str) -> String {
    format!("{phase}:{}", json!(value))
}

fn timestamp_policy(
    events: Arc<Mutex<Vec<String>>>,
    failure: Arc<AtomicU8>,
    on_update: bool,
) -> UserFieldConfig {
    let input_events = events.clone();
    let input_failure = failure.clone();
    let output_events = events.clone();
    let output_failure = failure.clone();
    UserFieldConfig {
        field_type: UserFieldType::Date,
        required: Some(false),
        on_update: on_update.then(|| {
            Arc::new(move || {
                trace_lock(&events)?.push("onUpdate".into());
                if failure.load(Ordering::SeqCst) == 1 {
                    return Err(AuthError::internal("ordinary updatedAt onUpdate error"));
                }
                Ok(date(GENERATED)?.into())
            }) as better_auth_core::user_fields::UserFieldFactory
        }),
        transform: Some(FieldTransforms {
            input: Some(UserFieldTransform::new(move |value| {
                trace_lock(&input_events)?.push(format!(
                    "input:{}",
                    required(value.json()?, "Expected the supplied timestamp")?
                ));
                if input_failure.load(Ordering::SeqCst) == 2 {
                    return Err(AuthError::internal("ordinary updatedAt input error"));
                }
                Ok(date(STORED)?.into())
            })),
            output: Some(UserFieldTransform::new(move |value| {
                trace_lock(&output_events)?.push(format!(
                    "output:{}",
                    required(value.json()?, "Expected the stored timestamp")?
                ));
                if output_failure.load(Ordering::SeqCst) == 3 {
                    return Err(AuthError::internal("ordinary updatedAt output error"));
                }
                Ok(date(PROJECTED)?.into())
            })),
        }),
        ..Default::default()
    }
}

async fn seed<S: AuthSchema>(raw: &dyn AuthStore<S>, hash: &str) -> AuthResult<ApiKey> {
    let mut fields = input(Some("Desk"), hash).into_adapter_fields()?;
    fields.extend([
        ("createdAt".into(), date(OLD)?.into()),
        ("updatedAt".into(), date(OLD)?.into()),
        ("lastRefillAt".into(), FieldValue::Null),
        ("lastRequest".into(), FieldValue::Null),
    ]);
    ApiKey::from_field_values(required(
        raw.create_api_key_record(fields).await?,
        "Expected the seeded API Key",
    )?)
}

async fn stored<S: AuthSchema>(raw: &dyn AuthStore<S>, key: &ApiKey) -> AuthResult<Value> {
    Ok(serde_json::to_value(required(
        raw.get_api_key_by_id_value(&key.id).await?,
        "Expected the complete stored API Key",
    )?)?)
}

async fn contract<S: AuthSchema>(raw: Arc<dyn AuthStore<S>>) -> AuthResult<()> {
    for declaration in ["native", "replacement", "on-update"] {
        let key = seed(raw.as_ref(), &format!("timestamp-{declaration}")).await?;
        let events = Arc::new(Mutex::new(Vec::new()));
        let failure = Arc::new(AtomicU8::new(0));
        let mut builder = BetterAuth::new(config())
            .store_arc(raw.clone())
            .plugin(ApiKeyPlugin::builder().build());
        let replacement = declaration != "native";
        let on_update = declaration == "on-update";
        if replacement {
            builder = builder.plugin(Fields(vec![(
                EntityRole::ApiKey,
                fields(
                    "updatedAt",
                    timestamp_policy(events.clone(), failure.clone(), on_update),
                ),
            )]));
        }
        let auth = builder.build().await?;
        let mut expected_stored = serde_json::to_value(&key)?;
        let mut expected_public = serde_json::to_value(ApiKeyView::try_from_api_key(&key)?)?;
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
        *required(
            expected_stored.get_mut("name"),
            "Expected name in the complete record",
        )? = json!("Mobile");
        *required(
            expected_stored.get_mut("updatedAt"),
            "Expected updatedAt in the complete record",
        )? = json!(if on_update { STORED } else { OLD });
        *required(
            expected_public.get_mut("name"),
            "Expected name in the complete record",
        )? = json!("Mobile");
        *required(
            expected_public.get_mut("updatedAt"),
            "Expected updatedAt in the complete record",
        )? = json!(if replacement { PROJECTED } else { OLD });
        assert_eq!(
            serde_json::to_value(updated)?,
            expected_public,
            "{declaration}"
        );
        assert_eq!(
            stored(raw.as_ref(), &key).await?,
            expected_stored,
            "{declaration}"
        );
        assert_eq!(
            *trace_lock(&events)?,
            if on_update {
                vec![
                    event("output", OLD),
                    "onUpdate".into(),
                    event("input", GENERATED),
                    event("output", STORED),
                ]
            } else if replacement {
                vec![event("output", OLD), event("output", OLD)]
            } else {
                Vec::new()
            },
            "{declaration}"
        );

        trace_lock(&events)?.clear();
        let updated = auth
            .store()
            .update_api_key(
                &key.id,
                UpdateApiKey {
                    name: Some(Some("Typed".into()).into()),
                    additional_fields: [("updatedAt".into(), date(SUPPLIED)?.into())].into(),
                    ..Default::default()
                },
            )
            .await?;
        *required(
            expected_stored.get_mut("name"),
            "Expected name in the complete record",
        )? = json!("Typed");
        *required(
            expected_stored.get_mut("updatedAt"),
            "Expected updatedAt in the complete record",
        )? = json!(if replacement { STORED } else { SUPPLIED });
        let mut expected_result = expected_stored.clone();
        if replacement {
            *required(
                expected_result.get_mut("updatedAt"),
                "Expected updatedAt in the complete record",
            )? = json!(PROJECTED);
        }
        assert_eq!(
            serde_json::to_value(updated)?,
            expected_result,
            "{declaration}"
        );
        assert_eq!(
            stored(raw.as_ref(), &key).await?,
            expected_stored,
            "{declaration}"
        );
        assert_eq!(
            *trace_lock(&events)?,
            if replacement {
                vec![event("input", SUPPLIED), event("output", STORED)]
            } else {
                Vec::new()
            }
        );

        trace_lock(&events)?.clear();
        let updated = required(
            auth.store()
                .write_api_key_usage(&key.id, ApiKeyUsageWrite::UpdatedAt(date(USAGE)?))
                .await?,
            "Expected the explicit usage timestamp write",
        )?;
        *required(
            expected_stored.get_mut("updatedAt"),
            "Expected updatedAt in the complete record",
        )? = json!(if replacement { STORED } else { USAGE });
        expected_result = expected_stored.clone();
        if replacement {
            *required(
                expected_result.get_mut("updatedAt"),
                "Expected updatedAt in the complete record",
            )? = json!(PROJECTED);
        }
        assert_eq!(serde_json::to_value(updated)?, expected_result);
        assert_eq!(stored(raw.as_ref(), &key).await?, expected_stored);
        assert_eq!(
            *trace_lock(&events)?,
            if replacement {
                vec![event("input", USAGE), event("output", STORED)]
            } else {
                Vec::new()
            }
        );

        if on_update {
            for (phase, name) in [(1, "onUpdate"), (2, "input"), (3, "output")] {
                trace_lock(&events)?.clear();
                failure.store(phase, Ordering::SeqCst);
                let error = auth
                    .store()
                    .update_api_key(
                        &key.id,
                        UpdateApiKey {
                            name: Some(Some("Rejected".into()).into()),
                            ..Default::default()
                        },
                    )
                    .await
                    .err()
                    .ok_or_else(|| {
                        AuthError::internal("Expected the timestamp callback failure")
                    })?;
                original_error(error, &format!("ordinary updatedAt {name} error"));
                if phase == 3 {
                    *required(
                        expected_stored.get_mut("name"),
                        "Expected name in the complete record",
                    )? = json!("Rejected");
                }
                assert_eq!(stored(raw.as_ref(), &key).await?, expected_stored, "{name}");
                let expected_events = [
                    "onUpdate".into(),
                    event("input", GENERATED),
                    event("output", STORED),
                ];
                assert_eq!(
                    *trace_lock(&events)?,
                    expected_events
                        .into_iter()
                        .take(usize::from(phase))
                        .collect::<Vec<_>>(),
                    "{name}"
                );
            }
        }
    }
    Ok(())
}

#[tokio::test]
async fn memory_updates_preserve_omitted_and_supplied_timestamp_policies() -> AuthResult<()> {
    contract(memory()).await
}

#[tokio::test]
async fn sqlite_updates_preserve_omitted_and_supplied_timestamp_policies() -> AuthResult<()> {
    contract(sqlite().await?).await
}
