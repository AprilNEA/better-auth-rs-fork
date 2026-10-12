#[path = "support/user_plugin_catalog.rs"]
mod catalog;

use better_auth::seaorm::{Database, sea_orm::DbBackend};

catalog::generated_schemas! {
    "BETTER_AUTH_USER_PLUGIN_CATALOG_SQLITE";
    default => ("default", "DEFAULT"),
    reversed => ("reversed", "REVERSED"),
    mapped => ("mapped", "MAPPED"),
    empty_mappings => ("empty-mappings", "EMPTY_MAPPINGS"),
    replaced => ("replaced", "REPLACED"),
    shared_columns => ("shared-columns", "SHARED_COLUMNS"),
    duplicate_plugins => ("duplicate-plugins", "DUPLICATE_PLUGINS"),
}

#[tokio::test]
async fn generated_user_plugin_catalog_matches_pinned_sqlite() -> catalog::TestResult {
    for case in catalog::cases("sqlite")? {
        let database = Database::connect("sqlite::memory:").await?;
        let result = async {
            let name = case["name"].as_str().ok_or("Missing catalog case name")?;
            let tables = create(&database, name).await?;
            catalog::check(&database, DbBackend::Sqlite, &case, tables).await
        }
        .await;
        database.close().await?;
        result?;
    }
    Ok(())
}
