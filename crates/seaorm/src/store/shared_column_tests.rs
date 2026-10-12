use better_auth_core::{
    AuthRecordFields, FieldMap, FieldValue,
    user_fields::{UserConfig, UserFieldConfig},
};
use sea_orm::{ActiveModelTrait, ConnectionTrait, Database, DbBackend};

use crate::{SeaOrmOrganizationModel, SeaOrmVerificationModel};

mod verification {
    use sea_orm::entity::prelude::*;

    #[derive(Clone, Debug, serde::Serialize, DeriveEntityModel, crate::AuthEntity)]
    #[sea_orm(table_name = "shared_verification")]
    #[auth(role = "verification")]
    pub struct Model {
        #[sea_orm(primary_key, auto_increment = false)]
        pub id: String,
        #[sea_orm(column_name = "shared")]
        #[auth(alias = "value")]
        pub identifier: String,
        pub expires_at: DateTimeUtc,
        pub created_at: DateTimeUtc,
        pub updated_at: DateTimeUtc,
    }

    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}
    impl ActiveModelBehavior for ActiveModel {}
}

mod organization {
    use sea_orm::entity::prelude::*;

    #[derive(Clone, Debug, serde::Serialize, DeriveEntityModel, crate::AuthEntity)]
    #[sea_orm(table_name = "shared_organization")]
    #[auth(role = "organization")]
    pub struct Model {
        #[sea_orm(primary_key, auto_increment = false)]
        pub id: String,
        #[sea_orm(column_name = "shared")]
        #[auth(alias = "slug")]
        pub name: String,
        pub logo: Option<String>,
        pub metadata: Option<serde_json::Value>,
        pub created_at: DateTimeUtc,
    }

    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}
    impl ActiveModelBehavior for ActiveModel {}
}

fn declarations(names: [&str; 2]) -> UserConfig {
    UserConfig {
        additional_fields: Some(
            names
                .into_iter()
                .map(|name| {
                    (
                        name.to_owned(),
                        UserFieldConfig {
                            field_name: Some("shared".into()),
                            ..Default::default()
                        },
                    )
                })
                .collect(),
        ),
    }
}

#[tokio::test]
async fn verification_aliases_share_typed_writes_and_project_every_logical_field()
-> Result<(), Box<dyn std::error::Error>> {
    let database = Database::connect("sqlite::memory:").await?;
    let _ = database.execute_unprepared("CREATE TABLE shared_verification (id TEXT PRIMARY KEY, shared TEXT NOT NULL, expires_at TEXT NOT NULL, created_at TEXT NOT NULL, updated_at TEXT NOT NULL)").await?;
    let date = chrono::DateTime::parse_from_rfc3339("2030-01-02T03:04:05.000Z")?.to_utc();
    let mut active =
        verification::Model::new_active(Some("verification".into()), &FieldMap::new())?;
    verification::Model::apply_fields(
        &mut active,
        FieldMap::from([
            ("identifier".into(), "first".into()),
            ("value".into(), "last".into()),
            ("expires_at".into(), date.into()),
            ("created_at".into(), date.into()),
            ("updated_at".into(), date.into()),
        ]),
    )?;
    let row = active.insert(&database).await?;
    assert_eq!(row.identifier, "last");
    let record = row
        .record(&declarations(["identifier", "value"]), false, true)
        .await?;
    assert_eq!(record.identifier, "last");
    assert_eq!(record.value, "last");
    assert_eq!(
        verification::Model::value_column(),
        verification::Model::identifier_column()
    );
    assert!(verification::Model::field_column("unknown").is_err());
    Ok(())
}

#[tokio::test]
async fn organization_aliases_preserve_projected_slots_without_duplicate_storage_members()
-> Result<(), Box<dyn std::error::Error>> {
    let database = Database::connect("sqlite::memory:").await?;
    let _ = database.execute_unprepared("CREATE TABLE shared_organization (id TEXT PRIMARY KEY, shared TEXT NOT NULL, logo TEXT, metadata TEXT, created_at TEXT NOT NULL)").await?;
    let date = chrono::DateTime::parse_from_rfc3339("2030-01-02T03:04:05.000Z")?.to_utc();
    let mut active = organization::ActiveModel::default();
    organization::Model::apply_fields(
        &mut active,
        FieldMap::from([
            ("id".into(), "organization".into()),
            ("name".into(), "first".into()),
            ("slug".into(), "last".into()),
            ("logo".into(), FieldValue::Null),
            ("metadata".into(), FieldValue::Null),
            ("created_at".into(), date.into()),
        ]),
    )?;
    let row = active.insert(&database).await?;
    assert_eq!(row.name, "last");
    let fields = declarations(["name", "slug"]);
    let record = row.record(&fields, DbBackend::Sqlite).await?;
    assert_eq!(record.name, "last");
    assert_eq!(record.slug, "last");
    let native = FieldMap::from([
        ("name".into(), FieldValue::Undefined),
        ("slug".into(), FieldValue::Null),
    ]);
    assert_eq!(
        row.record_from_fields(&fields, native.clone())?
            .field_values()?,
        native
    );
    assert!(organization::Model::column("unknown").is_err());
    Ok(())
}
