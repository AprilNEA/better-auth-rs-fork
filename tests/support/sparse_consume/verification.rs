use super::*;

const COLUMNS: &[&str] = &["id", "identifier", "value", "expires_at"];
const FUTURE: f64 = 4_102_444_800_000.0;

fn projected() -> FieldMap {
    let date = better_auth_core::FieldDate::from_milliseconds(FUTURE);
    FieldMap::from([
        ("identifier".into(), "subject".into()),
        ("value".into(), "visible:proof".into()),
        ("expiresAt".into(), date.clone().into()),
        ("createdAt".into(), date.clone().into()),
        ("updatedAt".into(), date.into()),
        ("id".into(), "target".into()),
    ])
}

fn callbacks() -> Vec<(&'static str, FieldValue)> {
    vec![
        ("value", "proof".into()),
        ("expiresAt", FUTURE.into()),
        ("createdAt", FUTURE.into()),
        ("updatedAt", FUTURE.into()),
    ]
}

pub(super) async fn check(database: &DatabaseConnection) -> TestResult {
    let _ = database.execute_unprepared(
        "CREATE TABLE verifications (id VARCHAR(64) PRIMARY KEY, identifier VARCHAR(64), value VARCHAR(64), expires_at DOUBLE PRECISION)",
    ).await?;
    for reject in [false, true] {
        let _ = database
            .execute_unprepared("DELETE FROM verifications")
            .await?;
        let _ = database.execute_unprepared(
            "INSERT INTO verifications VALUES ('older', 'subject', 'old-proof', 4102444799000), ('target', 'subject', 'proof', 4102444800000), ('unrelated', 'unrelated', 'retained-proof', 4102444800000)",
        ).await?;
        let observed = Events::default();
        let failure = Arc::new(AtomicBool::new(false));
        let output_calls = Arc::new(AtomicUsize::new(0));
        let output_events = observed.clone();
        let output_failure = failure.clone();
        let calls = output_calls.clone();
        let mut config =
            AuthConfig::new("sparse-verification-consume-secret-at-least-thirty-two-characters");
        let _ = config.verification.additional_fields.insert(
            "value".into(),
            UserFieldConfig {
                transform: Some(FieldTransforms {
                    output: Some(UserFieldTransform::new(move |value| {
                        events(&output_events)?.push(("value", value.clone()));
                        let count = calls.fetch_add(1, Ordering::SeqCst) + 1;
                        if output_failure.load(Ordering::SeqCst) && count == 2 {
                            return Err(AuthError::internal("sparse-verification-output"));
                        }
                        Ok(format!(
                            "visible:{}",
                            better_auth_core::SchemaValue::<String>::from_field(value)
                                .display_string()?
                        )
                        .into())
                    })),
                    ..Default::default()
                }),
                ..Default::default()
            },
        );
        for name in ["expiresAt", "createdAt", "updatedAt"] {
            let output_events = observed.clone();
            let _ = config.verification.additional_fields.insert(
                name.into(),
                UserFieldConfig {
                    field_name: Some("expires_at".into()),
                    field_type: UserFieldType::Date,
                    transform: Some(FieldTransforms {
                        output: Some(UserFieldTransform::new(move |value| {
                            events(&output_events)?.push((name, value.clone()));
                            better_auth_core::query::field_date(&value).map(FieldValue::Date)
                        })),
                        ..Default::default()
                    }),
                    ..Default::default()
                },
            );
        }
        let store = SeaOrmStore::<BundledSchema>::new(config, database.clone());
        let before = snapshot(database, "verifications", COLUMNS).await?;
        assert!(
            store
                .consume_verification("subject", "wrong")
                .await?
                .is_none()
        );
        assert_eq!(std::mem::take(&mut *events(&observed)?), callbacks());
        assert_eq!(snapshot(database, "verifications", COLUMNS).await?, before);
        output_calls.store(0, Ordering::SeqCst);
        failure.store(reject, Ordering::SeqCst);
        let result = store.consume_verification("subject", "visible:proof").await;
        if reject {
            assert!(
                matches!(result, Err(AuthError::Internal(message)) if message == "sparse-verification-output")
            );
        } else {
            assert_eq!(
                result?
                    .ok_or("Expected the sparse verification")?
                    .fields()?,
                projected()
            );
        }
        let mut expected_events = callbacks();
        if reject {
            expected_events.push(("value", "proof".into()));
        } else {
            expected_events.extend(callbacks());
        }
        assert_eq!(std::mem::take(&mut *events(&observed)?), expected_events);
        assert_eq!(output_calls.load(Ordering::SeqCst), 2);
        let retained = before
            .iter()
            .filter(|row| row.get("identifier") != Some(&FieldValue::from("subject")))
            .cloned()
            .collect::<Vec<_>>();
        assert_eq!(
            snapshot(database, "verifications", COLUMNS).await?,
            if reject { before } else { retained.clone() }
        );
        failure.store(false, Ordering::SeqCst);
        output_calls.store(0, Ordering::SeqCst);
        let retried = store
            .consume_verification("subject", "visible:proof")
            .await?;
        assert_eq!(
            retried.map(|row| row.fields()).transpose()?,
            reject.then(projected)
        );
        let expected_events = if reject {
            callbacks().into_iter().chain(callbacks()).collect()
        } else {
            Vec::new()
        };
        assert_eq!(std::mem::take(&mut *events(&observed)?), expected_events);
        assert_eq!(
            snapshot(database, "verifications", COLUMNS).await?,
            retained
        );
    }
    Ok(())
}
