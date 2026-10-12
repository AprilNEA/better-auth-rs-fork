#[path = "../../../../tests/support/native_plugin_replacement_contract.rs"]
mod contract;

use super::{plugin_catalog_rows, server_catalog_support::TestResult, sqlite_catalog};
use better_auth::{
    AuthSchema,
    seaorm::{
        Database, DatabaseConnection, SeaOrmAccountModel, SeaOrmPluginModel, SeaOrmPluginSchema,
        SeaOrmSessionModel, SeaOrmStore, SeaOrmUserModel, SeaOrmVerificationModel,
        sea_orm::EntityName,
    },
};
use serde_json::{Value, json};
use std::{path::Path, sync::Arc};

async fn check<S: AuthSchema, P: SeaOrmPluginSchema, M: SeaOrmPluginModel>(
    database: &DatabaseConnection,
    name: &str,
) -> TestResult
where
    S::User: SeaOrmUserModel,
    S::Session: SeaOrmSessionModel,
    S::Account: SeaOrmAccountModel,
    S::Verification: SeaOrmVerificationModel,
{
    assert!(contract::TARGETS.contains(&name));
    let expected = contract::fixture(
        &Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/fixtures/native-plugin-replacements-sqlite-1.7.6.json"),
        "sqlite",
        name,
    )?;
    let table = M::Entity::default().table_name().to_owned();
    assert_eq!(Some(table.as_str()), expected["table"].as_str());
    let target = contract::Target::from_fixture(&expected)?;
    assert!(
        !M::is_id_reference(&M::column(&target.column)?),
        "{name} replacement must remove the inherited ID reference"
    );
    for reference in expected["catalog"]["catalog"]["foreignKeys"]
        .as_array()
        .ok_or("Missing native replacement foreign keys")?
    {
        if reference["to"] == "id" {
            let column = reference["from"]
                .as_str()
                .ok_or("Missing native replacement reference column")?;
            assert!(
                M::is_id_reference(&M::column(column)?),
                "{name}.{column} must retain its declared ID reference"
            );
        }
    }
    let (catalog, ddl) = sqlite_catalog::observe(
        database,
        &table,
        "The generated native replacement table must exist",
    )
    .await?;
    eprintln!(
        "{}",
        json!({"case": expected["name"], "ddl": ddl, "upstreamDdl": expected["catalog"]["ddl"]})
    );
    assert_eq!(
        catalog, expected["catalog"]["catalog"],
        "{table} complete catalog"
    );
    let store =
        SeaOrmStore::<S>::new(contract::config(), database.clone()).with_plugin_schema::<P>();
    contract::with_store(Arc::new(store), "sqlite", expected, move || {
        let database = database.clone();
        async move {
            let rows = plugin_catalog_rows::stored::<M>(&database).await?;
            Ok(Value::Array(
                rows.into_iter()
                    .map(|row| {
                        let keys = row.keys().cloned().collect::<Vec<_>>();
                        json!({"row": row, "keys": keys})
                    })
                    .collect(),
            ))
        }
    })
    .await
}

macro_rules! target {
    ($module:ident, $schema:literal, $name:literal, $model:ident) => {
        mod $module {
            include!(env!($schema));

            #[tokio::test]
            async fn generated_sqlite_native_plugin_replacements_match_complete_operations()
            -> super::TestResult {
                let database = super::Database::connect("sqlite::memory:").await?;
                let result = async {
                    create_auth_tables(&database).await?;
                    super::check::<
                        AppAuthSchema,
                        AppPluginSchema,
                        <AppPluginSchema as super::SeaOrmPluginSchema>::$model,
                    >(&database, $name)
                    .await
                }
                .await;
                database.close().await?;
                result
            }
        }
    };
}
