use super::*;
use better_auth_core::{
    FieldValue, SchemaValue,
    schema::EntityRole,
    store::{AuthStore, schema::SchemaConfiguration},
    user_fields::UserConfig,
};
use better_auth_seaorm::{PluginModels, store::entities};

#[expect(
    unreachable_pub,
    reason = "SeaORM entity and enum derives require public fixture types"
)]
mod model {
    use better_auth_seaorm::{
        AuthEntity,
        sea_orm::{self, entity::prelude::*},
    };

    #[expect(
        clippy::enum_variant_names,
        reason = "SeaORM derives a sibling variant enum from the fixed PostgreSQL labels with a shared stored prefix"
    )]
    mod labels {
        use super::*;

        #[derive(Clone, Debug, PartialEq, Eq, EnumIter, DeriveActiveEnum)]
        #[sea_orm(rs_type = "String", db_type = "Enum", enum_name = "raw_jwk_label")]
        pub enum KeyLabel {
            #[sea_orm(string_value = "stored:source")]
            Source,
            #[sea_orm(string_value = "stored:next")]
            Next,
            #[sea_orm(string_value = "stored:reject")]
            Reject,
        }
    }

    pub use labels::KeyLabel;

    #[derive(Clone, Debug, PartialEq, DeriveEntityModel, AuthEntity)]
    #[auth(role = "jwk")]
    #[sea_orm(table_name = "raw_enum_jwks")]
    pub struct Model {
        #[sea_orm(primary_key, auto_increment = false)]
        pub id: String,
        #[sea_orm(column_name = "stored_public_key")]
        pub public_key: Option<KeyLabel>,
    }

    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}

    impl ActiveModelBehavior for ActiveModel {}
}

type Plugins = PluginModels<
    entities::api_key::Model,
    entities::device_code::Model,
    entities::passkey::Model,
    entities::two_factor::Model,
    model::Model,
>;

fn callback(events: &Events, phase: &'static str) -> UserFieldTransform {
    let events = events.clone();
    UserFieldTransform::new(move |value| {
        events
            .lock()
            .unwrap()
            .push(json!([phase, "publicKey", contract::observe(&value)?]));
        if value.is_null() {
            return Ok(value);
        }
        let label = SchemaValue::<String>::from_field(value).display_string()?;
        if phase == "output" && label == "stored:reject" {
            return Err(AuthError::internal("enum-output-stop"));
        }
        Ok(format!(
            "{}:{label}",
            if phase == "input" {
                "stored"
            } else {
                "visible"
            },
        )
        .into())
    })
}

async fn stored(database: &DatabaseConnection) -> TestResult<Value> {
    let columns = database
        .query_all_raw(Statement::from_string(
            DbBackend::Postgres,
            "SELECT column_name AS name FROM information_schema.columns WHERE table_schema = current_schema() AND table_name = 'raw_enum_jwks' ORDER BY ordinal_position",
        ))
        .await?
        .iter()
        .map(|row| row.try_get::<String>("", "name"))
        .collect::<Result<Vec<_>, _>>()?;
    let rows = database
        .query_all_raw(Statement::from_string(
            DbBackend::Postgres,
            "SELECT row_to_json(stored)::TEXT AS record FROM raw_enum_jwks AS stored ORDER BY id",
        ))
        .await?
        .iter()
        .map(|row| {
            Ok(serde_json::from_str::<Value>(
                &row.try_get::<String>("", "record")?,
            )?)
        })
        .collect::<TestResult<Vec<_>>>()?;
    for row in &rows {
        assert_eq!(
            row.as_object()
                .unwrap()
                .keys()
                .map(String::as_str)
                .collect::<Vec<_>>(),
            ["id", "stored_public_key"],
            "complete physical row order"
        );
    }
    Ok(json!({"columns": columns, "rows": rows}))
}

async fn check(database: DatabaseConnection) -> TestResult {
    for sql in [
        "CREATE TYPE raw_jwk_label AS ENUM ('stored:source', 'stored:next', 'stored:reject')",
        "CREATE TABLE raw_enum_jwks (id TEXT NOT NULL PRIMARY KEY, stored_public_key raw_jwk_label NULL)",
    ] {
        let _ = database.execute_unprepared(sql).await?;
    }
    let config = Arc::new(AuthConfig::new(
        "raw-enum-test-secret-at-least-thirty-two-characters",
    ));
    let raw: Arc<dyn AuthStore<BundledSchema>> = Arc::new(
        SeaOrmStore::<BundledSchema>::new(config.clone(), database.clone())
            .with_plugin_schema::<Plugins>(),
    );
    let events = Events::default();
    let mut fields = UserConfig::default();
    let _ = fields.fields_mut().insert(
        "publicKey".into(),
        UserFieldConfig {
            field_type: UserFieldType::String,
            field_name: Some("stored_public_key".into()),
            required: Some(false),
            transform: Some(FieldTransforms {
                input: Some(callback(&events, "input")),
                output: Some(callback(&events, "output")),
            }),
            ..Default::default()
        },
    );
    let mut model_fields = better_auth_core::plugin_runtime::ModelFields::default();
    model_fields.register_model_fields(EntityRole::Jwk, fields)?;
    let mut fields = model_fields;
    fields.set_schema_configuration(&SchemaConfiguration {
        config: config.clone(),
        plugins: Vec::new(),
        metadata: Default::default(),
        secondary_storage: false,
        rate_limit: Default::default(),
    });
    let store = raw.with_runtime(config, Vec::new(), fields)?;
    let id = SchemaValue::<String>::from("mapping-row");
    for (stage, label) in [
        ("create", Some("source")),
        ("read", Some("source")),
        ("list", Some("source")),
        ("update", Some("next")),
        ("read-updated", Some("next")),
        ("update-null", None),
        ("read-null", None),
        ("update-rejected", Some("reject")),
        ("read-rejected", Some("reject")),
        ("delete", None),
        ("create-rejected", Some("reject")),
        ("read-create-rejected", Some("reject")),
        ("delete-rejected", None),
        ("missing", None),
    ] {
        let present = !stage.starts_with("delete") && stage != "missing";
        let input = label.map_or(FieldValue::Null, FieldValue::from);
        let result: AuthResult<Vec<FieldMap>> = if stage.starts_with("create") {
            store
                .create_jwk_record(
                    [
                        ("id".into(), id.field_value()),
                        ("publicKey".into(), input.clone()),
                    ]
                    .into(),
                )
                .await
                .map(|row| row.into_iter().collect())
        } else if stage.starts_with("update") {
            store
                .update_jwk_record(&id, [("publicKey".into(), input.clone())].into())
                .await
                .map(|row| row.into_iter().collect())
        } else if stage.starts_with("delete") {
            store.delete_jwk_record(&id).await.map(|()| Vec::new())
        } else if stage == "list" {
            store.list_jwk_records().await
        } else {
            store
                .get_jwk_record(&id)
                .await
                .map(|row| row.into_iter().collect())
        };
        if present && label == Some("reject") {
            assert_eq!(
                result.unwrap_err().instrumentation_message(),
                "enum-output-stop",
                "{stage} output error"
            );
        } else {
            let expected = if present {
                vec![FieldMap::from([
                    (
                        "publicKey".into(),
                        label.map_or(FieldValue::Null, |label| {
                            format!("visible:stored:{label}").into()
                        }),
                    ),
                    ("id".into(), id.field_value()),
                ])]
            } else {
                Vec::new()
            };
            let result = result?;
            assert_eq!(result, expected, "{stage} complete result");
            for row in result {
                assert_eq!(
                    row.keys().map(String::as_str).collect::<Vec<_>>(),
                    ["publicKey", "id"],
                    "{stage} complete result key order"
                );
            }
        }
        let mut callbacks = Vec::new();
        if stage.starts_with("create") || stage.starts_with("update") {
            callbacks.push(json!(["input", "publicKey", label]));
        }
        if present {
            callbacks.push(json!([
                "output",
                "publicKey",
                label.map(|label| format!("stored:{label}"))
            ]));
        }
        assert_eq!(*events.lock().unwrap(), callbacks, "{stage} callbacks");
        events.lock().unwrap().clear();
        let rows = if present {
            vec![json!({
                "id": "mapping-row",
                "stored_public_key": label.map(|label| format!("stored:{label}")),
            })]
        } else {
            Vec::new()
        };
        assert_eq!(
            stored(&database).await?,
            json!({"columns": ["id", "stored_public_key"], "rows": rows}),
            "{stage} complete physical storage"
        );
    }
    Ok(())
}

#[tokio::test]
#[ignore = "Requires BETTER_AUTH_TEST_POSTGRES_URL and isolated schema permissions"]
async fn live_postgres_enum_labels_reach_crud_callbacks() -> TestResult {
    server::isolated("postgres", check).await
}
