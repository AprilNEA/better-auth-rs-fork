use better_auth::{
    __private_core::store::UserStore,
    AuthConfig, FieldMap,
    config::{UserFieldConfig, UserFieldType},
    seaorm::{
        Database, SeaOrmStore,
        sea_orm::{ConnectionTrait, DbBackend, EntityTrait, Statement},
    },
};
use serde_json::{Value, json};

mod sqlite {
    include!(env!("BETTER_AUTH_SHARED_DECLARATIONS_SQLITE_SCHEMA"));
}

mod postgres {
    include!(env!("BETTER_AUTH_SHARED_DECLARATIONS_POSTGRES_SCHEMA"));
}

mod mysql {
    include!(env!("BETTER_AUTH_SHARED_DECLARATIONS_MYSQL_SCHEMA"));
}

type TestResult = Result<(), Box<dyn std::error::Error>>;

#[tokio::test]
async fn shared_declarations_preserve_sqlite_json_text_and_native_column_names() -> TestResult {
    let database = Database::connect("sqlite::memory:").await?;
    sqlite::create_auth_tables(&database).await?;
    let mut config = AuthConfig::default();
    let _ = config.user.fields_mut().insert(
        "name".into(),
        UserFieldConfig {
            field_type: UserFieldType::Json,
            required: Some(true),
            ..Default::default()
        },
    );
    let _ = config.user.fields_mut().insert(
        "createdAt".into(),
        UserFieldConfig {
            field_type: UserFieldType::Date,
            required: Some(true),
            ..Default::default()
        },
    );
    let store = SeaOrmStore::<sqlite::AppAuthSchema>::new(config, database.clone());
    let date = "2030-01-02T03:04:05.000Z";
    let text = " { \"nested\": [1, true] } ";
    let created = store
        .create_user_fields_optional(FieldMap::from([
            ("name".into(), text.into()),
            ("email".into(), "shared-declarations@example.com".into()),
            ("emailVerified".into(), true.into()),
            ("createdAt".into(), date.into()),
            ("updatedAt".into(), date.into()),
        ]))
        .await?
        .ok_or("The declared User must be created")?;
    assert_eq!(
        created.name.field_value().json()?,
        Some(json!({ "nested": [1, true] }))
    );
    let row = sqlite::user::Entity::find_by_id(created.id.typed()?.as_str())
        .one(&database)
        .await?
        .ok_or("The User row must remain stored")?;
    assert_eq!(serde_json::to_value(&row.name)?, json!(text));
    let physical = database
        .query_one_raw(Statement::from_sql_and_values(
            DbBackend::Sqlite,
            "SELECT name, createdAt FROM user WHERE id = ?",
            [created.id.typed()?.clone().into()],
        ))
        .await?
        .ok_or("The physical User row must remain stored")?;
    assert_eq!(physical.try_get::<String>("", "name")?, text);
    assert_eq!(physical.try_get::<String>("", "createdAt")?, date);

    database
        .execute_raw(Statement::from_sql_and_values(
            DbBackend::Sqlite,
            "INSERT INTO organization (id, name, slug, logo, createdAt) VALUES (?, ?, ?, ?, ?)",
            [
                "shared-organization".into(),
                "Shared".into(),
                "shared".into(),
                text.into(),
                date.into(),
            ],
        ))
        .await?;
    let organization = sqlite::organization::Entity::find_by_id("shared-organization")
        .one(&database)
        .await?
        .ok_or("The declared Organization row must remain stored")?;
    assert_eq!(serde_json::to_value(&organization.logo)?, json!(text));
    database.execute_raw(Statement::from_sql_and_values(
        DbBackend::Sqlite,
        "INSERT INTO team (id, name, organizationId, memberCount, createdAt) VALUES (?, ?, ?, ?, ?)",
        ["shared-team".into(), "Shared".into(), "shared-organization".into(), 0_i64.into(), date.into()],
    )).await?;
    database.execute_raw(Statement::from_sql_and_values(
        DbBackend::Sqlite,
        "INSERT INTO teamMember (id, teamId, userId, createdAt, stored_label) VALUES (?, ?, ?, ?, ?)",
        ["shared-member".into(), "shared-team".into(), created.id.typed()?.clone().into(), date.into(), text.into()],
    )).await?;
    let row = sqlite::team_member::Entity::find_by_id("shared-member")
        .one(&database)
        .await?
        .ok_or("The declared TeamMember row must remain stored")?;
    assert_eq!(serde_json::to_value(&row.label)?, json!(text));

    let expected: Value = serde_json::from_str(include_str!(
        "../../../../tests/fixtures/shared-declarations-options-1.7.6.json"
    ))?;
    assert_eq!(expected["version"], "1.7.6");
    assert_eq!(expected["database"], "sqlite");
    let expected_models = expected["models"]
        .as_array()
        .ok_or("Expected model catalogs")?;
    let mut catalogs = Vec::new();
    for model in [
        "user",
        "session",
        "account",
        "verification",
        "organization",
        "member",
        "invitation",
        "team",
        "teamMember",
        "organizationRole",
        "rateLimit",
    ] {
        let (catalog, ddl) = better_auth_schema_consumer::sqlite_catalog::observe(
            &database,
            model,
            "The declared model must have a generated table",
        )
        .await?;
        eprintln!(
            "{}",
            json!({ "model": model, "catalog": catalog, "ddl": ddl })
        );
        let expected_model = expected_models
            .get(catalogs.len())
            .ok_or("Missing model catalog")?;
        assert_eq!(expected_model["model"], model);
        assert_eq!(
            catalog,
            json!({
                "table": expected_model["table"],
                "columns": expected_model["columns"],
                "indexes": expected_model["indexes"],
                "foreignKeys": expected_model["foreignKeys"],
            }),
            "{model}: complete SQLite catalog"
        );
        catalogs.push(catalog);
    }
    assert_eq!(catalogs.len(), expected_models.len());
    let rate_limit = catalogs.last().ok_or("The RateLimit catalog must exist")?;
    let columns = rate_limit
        .get("columns")
        .and_then(Value::as_array)
        .ok_or("Expected column metadata")?;
    assert_eq!(
        columns
            .iter()
            .map(|column| column["name"].clone())
            .collect::<Vec<_>>(),
        vec![
            json!("id"),
            json!("key"),
            json!("count"),
            json!("stored_last_request")
        ]
    );
    Ok(())
}
