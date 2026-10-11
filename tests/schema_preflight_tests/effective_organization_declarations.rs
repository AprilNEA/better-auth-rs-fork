use super::*;
use crate::sqlite_fixture_schema::{column_constraint, rewrite_empty_table};

async fn database() -> DatabaseConnection {
    let database = Database::connect("sqlite::memory:").await.unwrap();
    migrator::run_migrations(&database).await.unwrap();
    rewrite_empty_table(&database, "team", |sql| {
        ["name", "organization_id", "created_at"]
            .into_iter()
            .try_fold(sql.to_owned(), |sql, column| {
                column_constraint(&sql, column, "")
            })
    })
    .await
    .unwrap();
    database
}

async fn auth(
    database: &DatabaseConnection,
    partial: bool,
    events: &Events,
) -> BetterAuth<BundledSchema> {
    let settings = settings();
    let fields = if partial {
        declaration("organizationId", "name", events)
    } else {
        UserConfig {
            additional_fields: Some(Default::default()),
        }
    };
    AuthBuilder::new(settings.clone())
        .store(SeaOrmStore::<BundledSchema>::new(
            settings,
            database.clone(),
        ))
        .plugin(Fields(EntityRole::Team, fields))
        .build()
        .await
        .unwrap()
}

#[tokio::test]
async fn explicit_empty_and_partial_team_declarations_do_not_require_native_columns() {
    for partial in [false, true] {
        let database = database().await;
        for column in ["created_at", "updated_at"] {
            execute(&database, &format!("ALTER TABLE team DROP COLUMN {column}")).await;
        }
        let schema = sqlite::catalog(&database).await;
        let empty = sqlite::snapshot(&database).await;
        let events = Events::default();
        let auth = auth(&database, partial, &events).await;
        let response = http(&auth).await.unwrap();
        assert_eq!(response.status, 200);
        assert_eq!(
            serde_json::from_slice::<Value>(response.body.bytes().unwrap().as_ref()).unwrap(),
            json!({"ok":true})
        );
        assert!(events.lock().unwrap().is_empty());
        assert_eq!(sqlite::snapshot(&database).await, empty);
        assert_eq!(sqlite::catalog(&database).await, schema);
    }
}

#[tokio::test]
async fn explicit_team_declarations_control_complete_writes_and_readback() {
    for partial in [false, true] {
        let database = database().await;
        let schema = sqlite::catalog(&database).await;
        let empty = sqlite::snapshot(&database).await;
        let events = Events::default();
        let auth = auth(&database, partial, &events).await;
        assert_eq!(http(&auth).await.unwrap().status, 200);
        assert!(events.lock().unwrap().is_empty());
        let mut stages = vec![(Stage::Create, "source"), (Stage::Read, "source")];
        if partial {
            stages.extend([(Stage::Update, "next"), (Stage::Read, "next")]);
        }
        for (stage, input) in stages {
            let fields = records::run(Model::Team, stage, input, auth.store().as_ref()).await;
            let expected = if partial {
                json!({"organizationId":format!("visible:stored:{input}"),"id":ID})
            } else {
                json!({"id":ID})
            };
            assert_eq!(Value::Object(fields.json().unwrap()), expected);
            let keys = fields.keys().map(String::as_str).collect::<Vec<_>>();
            assert_eq!(
                keys,
                if partial {
                    vec!["organizationId", "id"]
                } else {
                    vec!["id"]
                }
            );
            let mut expected_events = Vec::new();
            if partial {
                if stage != Stage::Read {
                    expected_events.push(json!(["input", "organizationId", input]));
                }
                expected_events.push(json!([
                    "output",
                    "organizationId",
                    format!("stored:{input}")
                ]));
            }
            assert_eq!(*events.lock().unwrap(), expected_events);
            events.lock().unwrap().clear();
            let mut expected_storage = empty.clone();
            expected_storage.get_mut("team").unwrap().push(json!({
                "id":ID,
                "name": if partial { json!(format!("stored:{input}")) } else { Value::Null },
                "organization_id":null,
                "created_at":null,
                "updated_at":null,
                "member_count":0,
            }));
            assert_eq!(sqlite::snapshot(&database).await, expected_storage);
            assert_eq!(sqlite::catalog(&database).await, schema);
        }
    }
}

#[tokio::test]
async fn explicit_member_declarations_do_not_restore_filters_or_user_references() {
    for partial in [false, true] {
        for joins in [false, true] {
            let database = Database::connect("sqlite::memory:").await.unwrap();
            migrator::run_migrations(&database).await.unwrap();
            let empty = sqlite::snapshot(&database).await;
            let catalog = sqlite::catalog(&database).await;
            let events = Events::default();
            let fields = if partial {
                declaration("organizationId", "organization_id", &events)
            } else {
                UserConfig {
                    additional_fields: Some(Default::default()),
                }
            };
            let mut settings = settings();
            settings.advanced.database.joins = Some(joins);
            let auth = AuthBuilder::new(settings.clone())
                .store(SeaOrmStore::<BundledSchema>::new(
                    settings,
                    database.clone(),
                ))
                .plugin(Fields(EntityRole::Member, fields))
                .build()
                .await
                .unwrap();
            let error = auth
                .store()
                .get_member_by_id_with_user(ID)
                .await
                .unwrap_err();
            assert!(
                matches!(&error, AuthError::Config(message) if message == "No foreign key found for model user and base model member while performing join operation."),
                "{error}"
            );
            let error = auth
                .store()
                .query_organization_members(
                    &better_auth_core::store::ListOrganizationMembersParams {
                        organization_id: "source".into(),
                        filter_field: Some("userId".into()),
                        filter_value: Some("owner".into()),
                        ..Default::default()
                    },
                )
                .await
                .unwrap_err();
            let expected = if partial {
                "Field userId not found in model member"
            } else {
                "Field organizationId not found in model member"
            };
            assert!(
                matches!(&error, AuthError::Config(message) if message == expected),
                "{error}"
            );
            assert!(events.lock().unwrap().is_empty());
            assert_eq!(sqlite::snapshot(&database).await, empty);
            assert_eq!(sqlite::catalog(&database).await, catalog);
        }
    }
}

#[tokio::test]
async fn rust_organization_private_timestamp_alias_preserves_undefined_input() {
    let database = Database::connect("sqlite::memory:").await.unwrap();
    migrator::run_migrations(&database).await.unwrap();
    rewrite_empty_table(&database, "organization", |sql| {
        column_constraint(sql, "name", "")
    })
    .await
    .unwrap();
    let before = sqlite::snapshot(&database).await;
    let catalog = sqlite::catalog(&database).await;
    let events = Events::default();
    let mut fields = declaration("name", "auth_updated_at", &events);
    let input_events = events.clone();
    fields
        .fields_mut()
        .get_mut("name")
        .unwrap()
        .transform
        .as_mut()
        .unwrap()
        .input = Some(UserFieldTransform::new(move |value| {
        input_events
            .lock()
            .unwrap()
            .push(json!(["input", "name", value.json()?]));
        Ok(FieldValue::Undefined)
    }));
    let settings = settings();
    let auth = AuthBuilder::new(settings.clone())
        .store(SeaOrmStore::<BundledSchema>::new(
            settings,
            database.clone(),
        ))
        .plugin(OrganizationPlugin::new())
        .plugin(Fields(EntityRole::Organization, fields))
        .build()
        .await
        .unwrap();
    let response = http(&auth).await.unwrap();
    assert_eq!(response.status, 200);
    assert_eq!(
        serde_json::from_slice::<Value>(response.body.bytes().unwrap().as_ref()).unwrap(),
        json!({"ok": true})
    );
    assert!(events.lock().unwrap().is_empty());
    assert_eq!(sqlite::snapshot(&database).await, before);
    let error = auth
        .store()
        .create_organization(better_auth_core::CreateOrganization::new(
            "source", "source",
        ))
        .await
        .unwrap_err();
    assert!(
        matches!(
            &error,
            AuthError::Database(better_auth_core::error::DatabaseError::Query(message))
                if message == "Query Error: error returned from database: (code: 1299) NOT NULL constraint failed: organization.updated_at"
        ),
        "{error}"
    );
    assert_eq!(
        *events.lock().unwrap(),
        vec![json!(["input", "name", "source"])]
    );
    assert_eq!(sqlite::snapshot(&database).await, before);
    assert_eq!(sqlite::catalog(&database).await, catalog);
}
