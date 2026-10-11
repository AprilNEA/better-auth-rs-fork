#![cfg(feature = "seaorm2")]

use super::{Capture, config};
use better_auth_core::{
    AuthError, FieldFunction, FieldValue, SchemaValue, UpdateUser,
    store::UserStore,
    user_fields::{FieldTransforms, UserFieldConfig, UserFieldTransform},
};
use better_auth_seaorm::{
    SeaOrmStore,
    sea_orm::{ConnectOptions, ConnectionTrait, Database, EntityTrait, Schema},
    store::{__private_test_support::bundled_schema::BundledSchema, entities::user},
};
use serde_json::json;
use tracing::Instrument;

fn mark(phase: &'static str) {
    let _span = tracing::info_span!(target: "better-auth", "update_phase", "otel.name" = phase);
}

fn rejected_expression(phase: &'static str) -> FieldValue {
    FieldFunction::contextual(move |_, _| {
        mark(phase);
        Err(AuthError::internal(format!("{phase} rejected")))
    })
    .into()
}

// The factory wraps the raw adapter call after transformInput (factory.mjs:491).
#[tokio::test]
async fn ordinary_update_spans_include_name_and_expression_errors_after_input_policies()
-> Result<(), Box<dyn std::error::Error>> {
    for scenario in ["where-name", "set-parse", "where-parse", "input"] {
        let mut options = ConnectOptions::new("sqlite::memory:");
        let _ = options.max_connections(1);
        let database = Database::connect(options).await?;
        let _ = database
            .execute(
                &Schema::new(database.get_database_backend())
                    .create_table_from_entity(user::Entity),
            )
            .await?;
        let _ = database.execute_unprepared(
            "INSERT INTO users (id, name, email, email_verified, created_at, updated_at) \
             VALUES ('target', 'Before', 'target@update-span.test', 1, '2030-01-01T00:00:00.000Z', '2030-01-01T00:00:00.000Z')",
        ).await?;
        let before = user::Entity::find().all(&database).await?;
        let mut config = config();
        config.experimental.instrumentation.enabled = true;
        let _ = config.user.fields_mut().insert(
            "name".into(),
            UserFieldConfig {
                transform: Some(FieldTransforms {
                    input: Some(UserFieldTransform::new(move |value| {
                        mark("update input");
                        if scenario == "input" {
                            return Err(AuthError::internal("update input rejected"));
                        }
                        Ok(value)
                    })),
                    output: None,
                }),
                ..Default::default()
            },
        );
        if scenario == "where-name" {
            let _ = config.user.fields_mut().insert(
                "id".into(),
                UserFieldConfig {
                    field_name: Some("old_id".into()),
                    ..Default::default()
                },
            );
        }
        let store = SeaOrmStore::<BundledSchema>::new(config, database.clone());
        let selector = if scenario == "where-parse" {
            rejected_expression("update WHERE parse")
        } else {
            "target".into()
        };
        let name = if matches!(scenario, "set-parse" | "where-name") {
            rejected_expression("update SET parse")
        } else {
            "After".into()
        };
        let capture = Capture::default();
        let result = store
            .update_user_by_id_value(
                &selector,
                UpdateUser {
                    name: SchemaValue::from_field(name),
                    ..Default::default()
                },
            )
            .instrument(capture.span())
            .await;
        let error = result
            .err()
            .ok_or_else(|| AuthError::internal("Expected the UPDATE phase rejection"))?;
        let message = match scenario {
            "where-name" => "Field old_id not found in model user",
            "set-parse" => "update SET parse rejected",
            "where-parse" => "update WHERE parse rejected",
            _ => "update input rejected",
        };
        assert_eq!(error.instrumentation_message()?, message);
        capture.wait_closed().await?;
        {
            let records = capture
                .0
                .lock()
                .map_err(|_| AuthError::internal("capture poisoned"))?;
            let observed = records
                .iter()
                .map(|record| {
                    (
                        record
                            .fields
                            .get("otel.name")
                            .and_then(serde_json::Value::as_str),
                        record.parent.as_deref(),
                    )
                })
                .collect::<Vec<_>>();
            let mut expected = vec![(Some("update input"), None)];
            if scenario != "input" {
                expected.push((Some("db update users"), None));
            }
            if scenario == "set-parse" {
                expected.push((Some("update SET parse"), Some("db update users")));
            } else if scenario == "where-parse" {
                expected.push((Some("update WHERE parse"), Some("db update users")));
            }
            assert_eq!(observed, expected, "{scenario}");
            for record in records.iter() {
                assert_eq!(record.closed, 1);
                if record
                    .fields
                    .get("otel.name")
                    .and_then(serde_json::Value::as_str)
                    == Some("db update users")
                {
                    assert_eq!(
                        record.fields.get("db.collection.name"),
                        Some(&json!("users"))
                    );
                    assert_eq!(
                        record.fields.get("db.operation.name"),
                        Some(&json!("update"))
                    );
                    assert_eq!(record.fields.get("otel.status_code"), Some(&json!("ERROR")));
                    assert_eq!(
                        record.fields.get("otel.status_description"),
                        Some(&json!(message))
                    );
                    assert_eq!(record.exceptions, [message]);
                } else {
                    assert!(!record.fields.contains_key("otel.status_code"));
                    assert!(record.exceptions.is_empty());
                }
            }
        }
        assert_eq!(user::Entity::find().all(&database).await?, before);
    }
    Ok(())
}
