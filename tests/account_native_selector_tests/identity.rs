use super::*;
use better_auth_core::{FieldMap, SchemaValue, store::JoinValue};
use std::sync::atomic::{AtomicBool, Ordering};

#[tokio::test]
async fn memory_identity_queries_preserve_native_object_identity() -> AuthResult<()> {
    for joins in [false, true] {
        let mut config = AuthConfig::default();
        config.advanced.database.joins = Some(joins);
        let config = Arc::new(config);
        let inner = EphemeralStore::new(config.clone());
        let user = inner
            .create_user(CreateUser::new().with_email("object-provider@example.test"))
            .await?;
        let provider = FieldValue::from(FieldMap::from([("name".into(), "native".into())]));
        let distinct = FieldValue::from(FieldMap::from([("name".into(), "native".into())]));
        let mut expected = None;
        for (id, value) in [("selected", &provider), ("decoy", &distinct)] {
            let account = inner
                .create_account(CreateAccount {
                    id: id.into(),
                    provider_id: SchemaValue::from_field(value.clone()),
                    account_id: SchemaValue::from_field(7.into()),
                    user_id: user.id.clone(),
                    ..Default::default()
                })
                .await?;
            if id == "selected" {
                expected = Some(account.internal_fields()?);
            }
        }
        let before = inner.storage_rows(better_auth_core::store::schema::EntityRole::Account)?;
        let store = SecondaryStore::new(
            Arc::new(inner.clone()),
            Arc::new(MemoryCacheAdapter::new()),
            config,
            Default::default(),
        )?;
        let account = store
            .get_account_value(&provider, &7.into())
            .await?
            .unwrap();
        assert_eq!(account.internal_fields()?, expected.clone().unwrap());
        assert!(account.provider_id.field_value().strict_equals(&provider));
        let owner = store
            .get_account_owner_value(&provider, &7.into())
            .await?
            .unwrap();
        assert_eq!(owner.account.internal_fields()?, expected.unwrap());
        assert!(
            owner
                .account
                .provider_id
                .field_value()
                .strict_equals(&provider)
        );
        let JoinValue::One(Some(selected_user)) = owner.user else {
            return Err(AuthError::internal(
                "Native identity query must select one owner",
            ));
        };
        assert_eq!(selected_user, user);
        assert!(
            store
                .get_account_value(&provider, &"7".into())
                .await?
                .is_none()
        );
        let absent = FieldValue::from(FieldMap::from([("name".into(), "native".into())]));
        assert!(store.get_account_value(&absent, &7.into()).await?.is_none());
        assert!(
            store
                .get_account_owner_value(&absent, &7.into())
                .await?
                .is_none()
        );
        assert_eq!(
            inner.storage_rows(better_auth_core::store::schema::EntityRole::Account)?,
            before
        );
    }
    Ok(())
}

async fn select<S: AuthSchema>(
    store: &dyn AuthStore<S>,
    provider: &FieldValue,
    owner: bool,
) -> AuthResult<serde_json::Value> {
    if owner {
        let row = store
            .get_account_owner_value(provider, &7.into())
            .await?
            .unwrap();
        let JoinValue::One(Some(user)) = row.user else {
            return Err(AuthError::internal(
                "Native identity query must select one owner",
            ));
        };
        Ok(serde_json::json!({"account": row.account.internal_fields()?.json()?, "user": user}))
    } else {
        let row = store.get_account_value(provider, &7.into()).await?.unwrap();
        Ok(serde_json::Value::Object(row.internal_fields()?.json()?))
    }
}

async fn check_json_identity<S: AuthSchema>(
    base: Arc<dyn AuthStore<S>>,
    mut config: AuthConfig,
) -> AuthResult<()> {
    let user = base
        .create_user(CreateUser::new().with_email("json-provider@example.test"))
        .await?;
    let seed = |id: &str| CreateAccount {
        id: id.into(),
        provider_id: "ordinary-provider".into(),
        account_id: "ordinary-account".into(),
        user_id: user.id.clone(),
        refresh_token: Some("\"native-provider\"".to_owned()).into(),
        scope: SchemaValue::from_field(7.into()),
        ..Default::default()
    };
    let _ = base.create_account(seed("first")).await?;
    let events = Events::default();
    let fail_output = Arc::new(AtomicBool::new(false));
    let output_events = events.clone();
    let output_failure = fail_output.clone();
    let _ = config.account.additional_fields.insert(
        "providerId".into(),
        UserFieldConfig {
            field_name: Some("refreshToken".into()),
            field_type: UserFieldType::Json,
            transform: Some(FieldTransforms {
                input: Some(UserFieldTransform::new(|_| {
                    Err(AuthError::internal("Queries must not run input transforms"))
                })),
                output: Some(UserFieldTransform::new(move |value| {
                    output_events.lock().unwrap().push("output".into());
                    assert_eq!(value, FieldValue::from("native-provider"));
                    if output_failure.load(Ordering::SeqCst) {
                        return Err(AuthError::internal("native output failure"));
                    }
                    Ok(value)
                })),
            }),
            ..Default::default()
        },
    );
    let _ = config.account.additional_fields.insert(
        "accountId".into(),
        UserFieldConfig {
            field_name: Some("scope".into()),
            field_type: UserFieldType::Number,
            ..Default::default()
        },
    );
    config.advanced.database.default_find_many_limit = Some(1.0);
    let config = Arc::new(config);
    let reader = base.with_runtime(config.clone(), vec![], Default::default())?;
    let store = SecondaryStore::new(
        reader,
        Arc::new(MemoryCacheAdapter::new()),
        config,
        Default::default(),
    )?;
    let fail_query = Arc::new(AtomicBool::new(false));
    let query_failure = fail_query.clone();
    let query_events = events.clone();
    let marker = FieldValue::from(FieldMap::new());
    let observed_marker = marker.clone();
    let provider = FieldValue::from(FieldMap::from([
        ("marker".into(), marker),
        (
            "toJSON".into(),
            better_auth_core::FieldFunction::contextual(move |receiver, arguments| {
                assert_eq!(arguments, [FieldValue::from("")]);
                assert!(
                    receiver
                        .as_object()
                        .unwrap()
                        .get("marker")?
                        .unwrap()
                        .strict_equals(&observed_marker)
                );
                query_events.lock().unwrap().push("json".into());
                if query_failure.load(Ordering::SeqCst) {
                    return Err(AuthError::internal("native query failure"));
                }
                Ok("native-provider".into())
            })
            .into(),
        ),
    ]));
    let take = || std::mem::take(&mut *events.lock().unwrap());
    for duplicates in [false, true] {
        if duplicates {
            for id in ["second", "third"] {
                let _ = base.create_account(seed(id)).await?;
            }
        }
        let before = base.get_user_accounts(user.id.typed()?).await?;
        for owner in [false, true] {
            let expected = if duplicates {
                None
            } else {
                Some(select(&store, &"\"native-provider\"".into(), owner).await?)
            };
            let _ = take();
            for (query_error, output_error) in [(false, false), (true, false), (false, true)] {
                fail_query.store(query_error, Ordering::SeqCst);
                fail_output.store(output_error, Ordering::SeqCst);
                let result = select(&store, &provider, owner).await;
                let mut trace = vec!["json".to_owned()];
                if !query_error {
                    trace.extend(vec!["output".to_owned(); if duplicates { 2 } else { 1 }]);
                }
                let message = if query_error {
                    Some("native query failure")
                } else if output_error {
                    Some("native output failure")
                } else if duplicates {
                    trace.push("json".into());
                    Some(
                        "Multiple accounts match the same accountId for provider \"native-provider\". Resolve duplicate account identities before continuing.",
                    )
                } else {
                    None
                };
                if let Some(message) = message {
                    assert!(
                        matches!(result, Err(AuthError::Internal(actual)) if actual == message)
                    );
                } else {
                    assert_eq!(result?, expected.clone().unwrap());
                }
                assert_eq!(take(), trace);
                assert_eq!(base.get_user_accounts(user.id.typed()?).await?, before);
            }
            fail_query.store(false, Ordering::SeqCst);
            fail_output.store(false, Ordering::SeqCst);
        }
    }
    Ok(())
}

#[tokio::test]
async fn native_identity_queries_share_aliases_callbacks_and_duplicate_limits() -> AuthResult<()> {
    for joins in [false, true] {
        let mut config = AuthConfig::default();
        config.advanced.database.joins = Some(joins);
        check_json_identity(
            Arc::new(EphemeralStore::new(Arc::new(config.clone()))),
            config.clone(),
        )
        .await?;
        let database = Database::connect("sqlite::memory:").await.unwrap();
        migrator::run_migrations(&database).await.unwrap();
        check_json_identity(
            Arc::new(SeaOrmStore::<BundledSchema>::new(config.clone(), database)),
            config,
        )
        .await?;
    }
    Ok(())
}
