use super::*;
use better_auth_core::store::schema::{
    SchemaColumn, SchemaMismatch, SchemaTable, StoredSchemaTable, diff,
};

fn assert_ordered_mismatch(
    error: &SchemaCheckError,
    table: &str,
    missing: &[&str],
    required: &[&str],
) {
    let expected: Vec<_> = missing
        .iter()
        .map(|column| SchemaFinding::MissingColumn {
            table: table.into(),
            column: (*column).into(),
        })
        .chain(
            required
                .iter()
                .map(|column| SchemaFinding::UnexpectedRequiredColumn {
                    table: table.into(),
                    column: (*column).into(),
                }),
        )
        .collect();
    assert_eq!(findings(error), expected);
    let inner = mismatch_details(error);
    assert_eq!(
        serde_json::to_value(inner).unwrap(),
        json!({
            "code": "SCHEMA_MISMATCH", "source": "database", "findings": expected,
        })
    );
    let mut message = format!(
        "Database schema mismatch\n\n  Missing columns\n    {}",
        missing
            .iter()
            .map(|column| format!("{table}.{column}"))
            .collect::<Vec<_>>()
            .join("\n    ")
    );
    if !required.is_empty() {
        message.push_str(&format!("\n\n  Required columns Better Auth never writes\n    {}\n\n  Inserts into {table} will fail.", required.iter().map(|column| format!("{table}.{column}")).collect::<Vec<_>>().join("\n    ")));
    }
    message.push_str("\n\n  help: ");
    if !required.is_empty() {
        message.push_str(
            "Make the listed columns nullable, give them defaults, or remove them.\n        ",
        );
    }
    message.push_str("Run `npx auth migrate` to add the missing tables and columns.");
    assert_eq!(error.to_string(), message);
}

#[expect(
    unreachable_pub,
    reason = "SeaORM derives require public fixture entity types"
)]
mod numeric_user {
    use better_auth_seaorm::{
        AuthEntity,
        sea_orm::{self, entity::prelude::*},
    };

    #[derive(Clone, Debug, serde::Serialize, DeriveEntityModel, AuthEntity)]
    #[auth(role = "user")]
    #[sea_orm(table_name = "numeric_people")]
    pub struct Model {
        #[sea_orm(primary_key, auto_increment = false, column_name = "person_pk")]
        pub id: String,
        #[sea_orm(column_name = "10")]
        pub name: Option<String>,
        #[sea_orm(column_name = "2")]
        pub email: Option<String>,
        pub email_verified: bool,
        pub image: Option<String>,
        pub created_at: DateTimeUtc,
        pub updated_at: DateTimeUtc,
    }
    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}
    impl ActiveModelBehavior for ActiveModel {}
}

struct Numeric;
impl AuthSchema for Numeric {
    type User = numeric_user::Model;
    type Session = <BundledSchema as AuthSchema>::Session;
    type Account = <BundledSchema as AuthSchema>::Account;
    type Verification = <BundledSchema as AuthSchema>::Verification;
}

#[tokio::test]
async fn numeric_physical_aliases_follow_the_independent_primary_key() {
    let database = Database::connect("sqlite::memory:").await.unwrap();
    migrator::run_migrations(&database).await.unwrap();
    execute(&database, "CREATE TABLE numeric_people (email_verified BLOB, image BLOB, created_at BLOB, updated_at BLOB)").await;
    let before = sqlite::snapshot(&database).await;
    let catalog = sqlite::catalog(&database).await;
    let events = Events::default();
    let mut settings = settings();
    settings.user = declaration("name", "10", &events);
    settings
        .user
        .fields_mut()
        .extend(declaration("email", "2", &events).fields().clone());
    let store = SeaOrmStore::<Numeric>::new(settings.clone(), database.clone());
    let auth = AuthBuilder::new(settings)
        .store(store)
        .build()
        .await
        .unwrap();
    let error = mismatch(
        auth.handle_request(AuthRequest::new(HttpMethod::Get, "/api/auth/ok"))
            .await
            .unwrap_err(),
    );
    assert_ordered_mismatch(&error, "numeric_people", &["person_pk", "2", "10"], &[]);
    assert!(events.lock().unwrap().is_empty());
    assert_eq!(sqlite::snapshot(&database).await, before);
    assert_eq!(sqlite::catalog(&database).await, catalog);
}

#[tokio::test]
async fn numeric_organization_declarations_precede_native_fields_before_mapping() {
    let database = Database::connect("sqlite::memory:").await.unwrap();
    migrator::run_migrations(&database).await.unwrap();
    execute(&database, "DROP TABLE organization").await;
    execute(&database, "CREATE TABLE organization (updated_at BLOB)").await;
    let before = sqlite::snapshot(&database).await;
    let catalog = sqlite::catalog(&database).await;
    let events = Events::default();
    let mut fields = UserConfig::default();
    for (logical, physical) in [
        ("tail", "metadata"),
        ("10", "slug"),
        ("2", "logo"),
        ("01", "name"),
        ("4294967294", "createdAt"),
        ("4294967295", "metadata"),
    ] {
        fields
            .fields_mut()
            .extend(declaration(logical, physical, &events).fields().clone());
    }
    let settings = settings();
    let store = SeaOrmStore::<BundledSchema>::new(settings.clone(), database.clone());
    let auth = AuthBuilder::new(settings)
        .store(store)
        .plugin(OrganizationPlugin::new())
        .plugin(Fields(EntityRole::Organization, fields))
        .build()
        .await
        .unwrap();
    let error = mismatch(http(&auth).await.unwrap_err());
    assert_ordered_mismatch(
        &error,
        "organization",
        &["id", "logo", "slug", "created_at", "name", "metadata"],
        &[],
    );
    assert!(events.lock().unwrap().is_empty());
    assert_eq!(sqlite::snapshot(&database).await, before);
    assert_eq!(sqlite::catalog(&database).await, catalog);
}

#[test]
fn shared_physical_table_orders_merged_fields_after_the_independent_primary_key() {
    for id_column in ["id", "20"] {
        let expected = [
            SchemaTable {
                name: "shared".into(),
                schema: None,
                id_column: id_column.into(),
                columns: ["tail", "10", "01", "4294967294", "4294967295", id_column]
                    .into_iter()
                    .map(str::to_owned)
                    .collect(),
                disable_migrations: true,
            },
            SchemaTable {
                name: "shared".into(),
                schema: None,
                id_column: id_column.into(),
                columns: ["2", "10", "other"]
                    .into_iter()
                    .map(str::to_owned)
                    .collect(),
                disable_migrations: false,
            },
        ];
        let actual = [StoredSchemaTable {
            name: "shared".into(),
            schema: None,
            columns: [
                ("legacy-z", false, false),
                ("legacy-a", false, false),
                ("optional", true, false),
                ("defaulted", false, true),
            ]
            .into_iter()
            .map(|(name, nullable, has_default)| SchemaColumn {
                name: name.into(),
                nullable,
                has_default,
            })
            .collect(),
        }];
        let error = SchemaCheckError::Mismatch(SchemaMismatch::new(diff(&expected, &actual)));
        assert_ordered_mismatch(
            &error,
            "shared",
            &[
                id_column,
                "2",
                "10",
                "4294967294",
                "tail",
                "01",
                "4294967295",
                "other",
            ],
            &["legacy-z", "legacy-a"],
        );
    }
}

#[test]
fn numeric_physical_table_names_follow_javascript_property_order() {
    let expected: Vec<_> = ["tail", "10", "2", "01", "4294967294", "4294967295"]
        .into_iter()
        .map(|name| SchemaTable {
            name: name.into(),
            schema: None,
            id_column: "id".into(),
            columns: Vec::new(),
            disable_migrations: false,
        })
        .collect();
    let error = SchemaMismatch::new(diff(&expected, &[]));
    assert_eq!(
        serde_json::to_value(&error).unwrap(),
        json!({
            "code": "SCHEMA_MISMATCH", "source": "database",
            "findings": (["2", "10", "4294967294", "tail", "01", "4294967295"]
                .map(|table| json!({"kind": "missing-table", "table": table}))),
        })
    );
    assert_eq!(
        error.to_string(),
        "Database schema mismatch\n\n  Missing tables\n    2, 10, 4294967294, tail, 01, 4294967295\n\n  help: Run `npx auth migrate` to add the missing tables and columns."
    );
}

#[test]
fn equal_numeric_table_names_preserve_namespace_selection_and_stable_order() {
    let expected: Vec<_> = [
        ("10", Some("z_schema"), "from_z"),
        ("tail", None, "tail"),
        ("2", None, "two"),
        ("10", Some("a_schema"), "from_a"),
    ]
    .into_iter()
    .map(|(name, schema, column)| SchemaTable {
        name: name.into(),
        schema: schema.map(str::to_owned),
        id_column: "id".into(),
        columns: vec![column.into()],
        disable_migrations: false,
    })
    .collect();
    let actual: Vec<_> = [
        ("10", Some("a_schema"), "from_z"),
        ("10", Some("z_schema"), "from_a"),
        ("tail", None, "unwritten"),
        ("2", None, "unwritten"),
    ]
    .into_iter()
    .map(|(name, schema, column)| StoredSchemaTable {
        name: name.into(),
        schema: schema.map(str::to_owned),
        columns: ["id", column]
            .map(|name| SchemaColumn {
                name: name.into(),
                nullable: true,
                has_default: false,
            })
            .into(),
    })
    .collect();
    let error = SchemaMismatch::new(diff(&expected, &actual));
    assert_eq!(
        serde_json::to_value(&error).unwrap(),
        json!({
            "code": "SCHEMA_MISMATCH", "source": "database", "findings": [
                {"kind": "missing-column", "table": "2", "column": "two"},
                {"kind": "missing-column", "table": "10", "column": "from_z"},
                {"kind": "missing-column", "table": "10", "column": "from_a"},
                {"kind": "missing-column", "table": "tail", "column": "tail"},
            ],
        })
    );
    assert_eq!(
        error.to_string(),
        "Database schema mismatch\n\n  Missing columns\n    2.two\n    10.from_z\n    10.from_a\n    tail.tail\n\n  help: Run `npx auth migrate` to add the missing tables and columns."
    );
}
