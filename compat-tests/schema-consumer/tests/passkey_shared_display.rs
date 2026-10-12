#[path = "../../../tests/support/passkey_shared_display_contract.rs"]
mod contract;
use better_auth_schema_consumer::sqlite_catalog;

use better_auth::{
    AuthSchema,
    seaorm::{
        Database, DatabaseConnection, SeaOrmAccountModel, SeaOrmPluginSchema, SeaOrmSessionModel,
        SeaOrmStore, SeaOrmUserModel, SeaOrmVerificationModel,
    },
};
use contract::TestResult;
use serde_json::{Value, json};
use std::sync::Arc;

mod forward {
    include!(env!("BETTER_AUTH_PASSKEY_SHARED_DISPLAY_FORWARD_SCHEMA"));
}
mod reversed {
    include!(env!("BETTER_AUTH_PASSKEY_SHARED_DISPLAY_REVERSED_SCHEMA"));
}

fn cases() -> TestResult<Vec<Value>> {
    let fixture: Value = serde_json::from_str(include_str!(
        "../../../tests/fixtures/passkey-shared-display-1.7.6.json"
    ))?;
    assert_eq!(fixture["version"], "1.7.6");
    let cases = fixture["cases"]
        .as_array()
        .ok_or("Missing shared Passkey cases")?;
    assert_eq!(cases.len(), 4);
    let cases = cases
        .iter()
        .filter(|case| case["backend"] == "sqlite")
        .cloned()
        .collect::<Vec<_>>();
    assert_eq!(
        cases
            .iter()
            .map(|case| &case["declarationOrder"])
            .collect::<Vec<_>>(),
        [&json!(["name", "aaguid"]), &json!(["aaguid", "name"])]
    );
    Ok(cases)
}

async fn run<S: AuthSchema, P: SeaOrmPluginSchema>(
    database: &DatabaseConnection,
    case: &Value,
) -> TestResult
where
    S::User: SeaOrmUserModel,
    S::Session: SeaOrmSessionModel,
    S::Account: SeaOrmAccountModel,
    S::Verification: SeaOrmVerificationModel,
{
    assert_eq!(case["table"], "shared_display_passkey");
    assert_eq!(case["column"], "display");
    let (catalog, ddl) = sqlite_catalog::observe(
        database,
        "shared_display_passkey",
        "The generated shared Passkey table must exist",
    )
    .await?;
    assert_eq!(
        catalog, case["catalog"]["catalog"],
        "Complete generated SQLite catalog, including column order, defaults, index metadata, xinfo, and foreign keys"
    );
    assert_eq!(
        sqlite_catalog::ddl_declarations(&ddl)?,
        sqlite_catalog::ddl_declarations(&case["catalog"]["ddl"])?
    );
    eprintln!(
        "{}",
        json!({
            "contract":"passkey-shared-display",
            "declarationOrder":case["declarationOrder"],
            "ddlSyntaxBoundary":"SQLite catalog semantics are compared strictly; original DDL spelling is retained without text equality",
            "rustDdl":ddl,
            "upstreamDdl":case["catalog"]["ddl"],
        })
    );
    let store =
        SeaOrmStore::<S>::new(contract::config(), database.clone()).with_plugin_schema::<P>();
    contract::run(Arc::new(store), Some(database), case).await
}

#[tokio::test]
async fn generated_sqlite_shared_passkey_display_matches_pinned_catalog_and_operations()
-> TestResult {
    for case in cases()? {
        let database = Database::connect("sqlite::memory:").await?;
        let result = if case["declarationOrder"] == json!(["name", "aaguid"]) {
            forward::create_auth_tables(&database).await?;
            run::<forward::AppAuthSchema, forward::AppPluginSchema>(&database, &case).await
        } else {
            reversed::create_auth_tables(&database).await?;
            run::<reversed::AppAuthSchema, reversed::AppPluginSchema>(&database, &case).await
        };
        database.close().await?;
        result?;
    }
    Ok(())
}
