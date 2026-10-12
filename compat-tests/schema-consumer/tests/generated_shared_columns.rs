use better_auth_schema_consumer::sqlite_catalog;

use better_auth::seaorm::Database;
use serde_json::{Value, json};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

#[expect(
    dead_code,
    reason = "The catalog contract compiles each complete generated schema; Store contracts exercise the adapter aliases"
)]
mod native_string {
    include!(env!(
        "BETTER_AUTH_SHARED_COLUMNS_NATIVE_NATIVE_STRING_SCHEMA"
    ));
}

#[expect(
    dead_code,
    reason = "The catalog contract compiles each complete generated schema; Store contracts exercise the adapter aliases"
)]
mod native_number {
    include!(env!(
        "BETTER_AUTH_SHARED_COLUMNS_NATIVE_NATIVE_NUMBER_SCHEMA"
    ));
}

#[expect(
    dead_code,
    reason = "The catalog contract compiles each complete generated schema; Store contracts exercise the adapter aliases"
)]
mod additional {
    include!(env!("BETTER_AUTH_SHARED_COLUMNS_NATIVE_ADDITIONAL_SCHEMA"));
}

#[tokio::test]
async fn all_shared_columns_compile_and_match_the_complete_pinned_sqlite_catalog() -> TestResult {
    let fixture: Value = serde_json::from_str(include_str!(
        "../../../tests/fixtures/shared-column-1.7.6.json"
    ))?;
    let observation = fixture
        .as_array()
        .ok_or("Missing backend observations")?
        .iter()
        .find(|observation| observation["backend"] == "sqlite")
        .ok_or("Missing SQLite observation")?;
    assert_eq!(observation["version"], "1.7.6");
    let cases = observation["cases"]
        .as_array()
        .ok_or("Missing shared-column cases")?;
    assert_eq!(cases.len(), 30);
    for mode in [
        "native-native-string",
        "native-native-number",
        "native-additional",
    ] {
        let database = Database::connect("sqlite::memory:").await?;
        match mode {
            "native-native-string" => native_string::create_auth_tables(&database).await?,
            "native-native-number" => native_number::create_auth_tables(&database).await?,
            "native-additional" => additional::create_auth_tables(&database).await?,
            _ => unreachable!(),
        }
        let selected = cases
            .iter()
            .filter(|case| case["mode"] == mode)
            .collect::<Vec<_>>();
        assert_eq!(selected.len(), 10);
        for case in selected {
            let table = case["catalog"]["catalog"]["table"]["name"]
                .as_str()
                .ok_or("Missing captured shared-column table")?;
            let (catalog, ddl) = sqlite_catalog::observe(
                &database,
                table,
                "The generated shared-column table must exist",
            )
            .await?;
            assert_eq!(
                catalog, case["catalog"]["catalog"],
                "Complete generated SQLite catalog for {} {mode}",
                case["model"]
            );
            assert_eq!(
                sqlite_catalog::ddl_declarations(&ddl)?,
                sqlite_catalog::ddl_declarations(&case["catalog"]["ddl"])?,
                "SQLite DDL objects for {} {mode}",
                case["model"]
            );
            eprintln!(
                "{}",
                json!({
                    "contract": "shared-column",
                    "model": case["model"],
                    "mode": mode,
                    "ddlSyntaxBoundary": "SQLite catalog semantics are compared strictly; original DDL spelling is retained without text equality",
                    "rustDdl": ddl,
                    "upstreamDdl": case["catalog"]["ddl"],
                })
            );
        }
        database.close().await?;
    }
    Ok(())
}
