#[path = "support/user_plugin_catalog.rs"]
mod catalog;

use better_auth::seaorm::sea_orm::DbBackend;
use better_auth_schema_consumer::server_catalog_support;

catalog::generated_schemas! {
    "BETTER_AUTH_USER_PLUGIN_CATALOG_POSTGRES";
    default => ("default", "DEFAULT"),
    reversed => ("reversed", "REVERSED"),
    mapped => ("mapped", "MAPPED"),
    empty_mappings => ("empty-mappings", "EMPTY_MAPPINGS"),
    replaced => ("replaced", "REPLACED"),
    shared_columns => ("shared-columns", "SHARED_COLUMNS"),
    duplicate_plugins => ("duplicate-plugins", "DUPLICATE_PLUGINS"),
}

#[tokio::test]
#[ignore = "Requires BETTER_AUTH_TEST_POSTGRES_URL and the CI upstream catalog fixture"]
async fn live_postgres_user_plugin_catalog_matches_pinned_upstream() -> catalog::TestResult {
    for case in catalog::cases("postgres")? {
        server_catalog_support::in_postgres_catalog(|database| async move {
            let name = case["name"].as_str().ok_or("Missing catalog case name")?;
            let tables = create(&database, name).await?;
            catalog::check(&database, DbBackend::Postgres, &case, tables).await
        })
        .await?;
    }
    Ok(())
}
