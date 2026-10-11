use super::*;

const COLUMNS: &[&str] = &[
    "id",
    "device_code",
    "client_id",
    "user_id",
    "status",
    "scope",
];

fn projected() -> AuthResult<DeviceCode> {
    DeviceCode::from_field_values(FieldMap::from([
        ("deviceCode".into(), "device".into()),
        ("clientId".into(), "client".into()),
        ("userId".into(), "owner".into()),
        ("status".into(), "approved".into()),
        (
            "scope".into(),
            FieldMap::from([("label".into(), "current".into())]).into(),
        ),
        ("id".into(), "target".into()),
    ]))
}

pub(super) async fn check(database: &DatabaseConnection) -> TestResult {
    let _ = database.execute_unprepared(
        "CREATE TABLE device_code (id VARCHAR(64) PRIMARY KEY, device_code VARCHAR(64), client_id VARCHAR(64), user_id VARCHAR(64), status VARCHAR(64), scope VARCHAR(64))",
    ).await?;
    for transactional in [false, true] {
        for reject in [false, true] {
            let _ = database
                .execute_unprepared("DELETE FROM device_code")
                .await?;
            let _ = database.execute_unprepared(
                "INSERT INTO device_code VALUES ('target', 'device', 'client', 'owner', 'approved', 'initial'), ('unrelated', 'unrelated-device', 'client', 'other-owner', 'approved', 'retained')",
            ).await?;
            let observed = Events::default();
            let failure = Arc::new(AtomicBool::new(false));
            let output_events = observed.clone();
            let output_failure = failure.clone();
            let fields = UserConfig {
                additional_fields: Some(
                    [
                        ("deviceCode".into(), UserFieldConfig::default()),
                        ("clientId".into(), UserFieldConfig::default()),
                        ("userId".into(), UserFieldConfig::default()),
                        ("status".into(), UserFieldConfig::default()),
                        (
                            "scope".into(),
                            UserFieldConfig {
                                transform: Some(FieldTransforms {
                                    output: Some(UserFieldTransform::new(move |value| {
                                        events(&output_events)?.push(("scope", value.clone()));
                                        if output_failure.load(Ordering::SeqCst) {
                                            return Err(AuthError::internal(
                                                "sparse-device-output",
                                            ));
                                        }
                                        Ok(FieldMap::from([("label".into(), value)]).into())
                                    })),
                                    ..Default::default()
                                }),
                                ..Default::default()
                            },
                        ),
                    ]
                    .into(),
                ),
            };
            let config = Arc::new(AuthConfig::new(
                "sparse-device-consume-secret-at-least-thirty-two-characters",
            ));
            let raw: Arc<dyn AuthStore<BundledSchema>> = Arc::new(
                SeaOrmStore::<BundledSchema>::new(config.clone(), database.clone()),
            );
            let mut model_fields = better_auth_core::plugin_runtime::ModelFields::default();
            model_fields.register_model_fields(EntityRole::DeviceCode, fields)?;
            let mut fields = model_fields;
            fields.set_schema_configuration(&SchemaConfiguration {
                config: config.clone(),
                plugins: Vec::new(),
                metadata: Default::default(),
                secondary_storage: false,
                rate_limit: Default::default(),
            });
            let store = raw.with_runtime(config, Vec::new(), fields)?;
            let expected = store
                .get_device_code_by_device_code("device")
                .await?
                .ok_or("Expected the sparse Device candidate")?;
            assert_eq!(
                std::mem::take(&mut *events(&observed)?),
                vec![("scope", "initial".into())]
            );
            let _ = database
                .execute_unprepared("UPDATE device_code SET scope = 'current' WHERE id = 'target'")
                .await?;
            let before = snapshot(database, "device_code", COLUMNS).await?;
            assert!(
                store
                    .consume_device_code(&expected, &DeviceCodeOwnership::ClientId("wrong".into()))
                    .await?
                    .is_none()
            );
            assert!(events(&observed)?.is_empty());
            assert_eq!(snapshot(database, "device_code", COLUMNS).await?, before);

            failure.store(reject, Ordering::SeqCst);
            let ownership = DeviceCodeOwnership::ClientId("client".into());
            let result = if transactional {
                let selected = expected.clone();
                let ownership = ownership.clone();
                transaction(store.as_ref(), move |tx| {
                    Box::pin(async move { tx.consume_device_code(&selected, &ownership).await })
                })
                .await
            } else {
                store.consume_device_code(&expected, &ownership).await
            };
            if reject {
                assert!(
                    matches!(result, Err(AuthError::Internal(message)) if message == "sparse-device-output")
                );
            } else {
                assert_eq!(result?, Some(projected()?));
            }
            assert_eq!(
                std::mem::take(&mut *events(&observed)?),
                vec![("scope", "current".into())]
            );
            let retained = before
                .iter()
                .filter(|row| row.get("id") != Some(&FieldValue::from("target")))
                .cloned()
                .collect::<Vec<_>>();
            assert_eq!(
                snapshot(database, "device_code", COLUMNS).await?,
                if transactional && reject {
                    before
                } else {
                    retained.clone()
                }
            );
            failure.store(false, Ordering::SeqCst);
            let retried = store.consume_device_code(&expected, &ownership).await?;
            assert_eq!(
                retried,
                if transactional && reject {
                    Some(projected()?)
                } else {
                    None
                }
            );
            assert_eq!(
                std::mem::take(&mut *events(&observed)?),
                if transactional && reject {
                    vec![("scope", "current".into())]
                } else {
                    Vec::new()
                }
            );
            assert_eq!(snapshot(database, "device_code", COLUMNS).await?, retained);
        }
    }
    Ok(())
}
