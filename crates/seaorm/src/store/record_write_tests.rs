use super::*;
use crate::{SeaOrmPluginModel, store::entities::passkey};
use better_auth_core::{
    AuthError, FieldMap,
    id::IdGeneration,
    user_fields::{FieldTransforms, UserConfig, UserFieldConfig, UserFieldTransform},
};

#[tokio::test]
async fn declared_undefined_keeps_database_default_instead_of_legacy_initializer() -> AuthResult<()>
{
    let db = sea_orm::Database::connect("sqlite::memory:")
        .await
        .map_err(map_db_err)?;
    let _ = db.execute_unprepared(
        "CREATE TABLE passkeys (id TEXT PRIMARY KEY, updated_at TEXT DEFAULT 'database-default')",
    ).await.map_err(map_db_err)?;
    let mut schema = UserConfig::default();
    let _ = schema.fields_mut().insert(
        "label".into(),
        UserFieldConfig {
            field_name: Some("updatedAt".into()),
            transform: Some(FieldTransforms {
                input: Some(UserFieldTransform::new(|_| Ok(FieldValue::Undefined))),
                output: None,
            }),
            ..Default::default()
        },
    );
    let input = schema
        .storage_fields_with_bound_id(
            FieldMap::from([("label".into(), "supplied".into())]),
            true,
            || Ok(Some("row".into())),
            |_, _, value| Ok(value),
        )
        .await?;
    let write = RecordWrite::<passkey::Entity>::from_initialized_fields::<passkey::ActiveModel>(
        &schema,
        input,
        passkey::Model::column,
        vec![passkey::Column::UpdatedAt],
        |_| {
            Err(AuthError::internal(
                "A declared column must not call the legacy initializer",
            ))
        },
    )?;
    let row = write
        .insert_raw(
            &db,
            CreateReadback {
                schema: &schema,
                policy: &IdGeneration::Database,
                scope: super::super::create_readback::ReadbackScope::Direct(&db),
                column: passkey::Model::column,
            },
        )
        .await?
        .ok_or_else(|| AuthError::internal("Created row was not returned"))?;
    assert_eq!(row.try_get::<String>("", "id").map_err(map_db_err)?, "row");
    assert_eq!(
        row.try_get::<String>("", "updated_at")
            .map_err(map_db_err)?,
        "database-default"
    );
    Ok(())
}
