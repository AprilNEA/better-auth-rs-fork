use better_auth::seaorm::{DatabaseConnection, sea_orm::DbBackend};
use better_auth_schema_consumer::{server_catalog_indexes, server_catalog_support, sqlite_catalog};
use serde_json::{Map, Value, json};

#[path = "../../../../tests/support/observation_replay.rs"]
mod observation_replay;

use observation_replay::assert_replay;

pub use server_catalog_support::TestResult;

macro_rules! generated_schemas {
    ($prefix:literal; $($module:ident => ($name:literal, $suffix:literal)),+ $(,)?) => {
        $(
            #[expect(
                dead_code,
                reason = "The catalog contract compiles each complete generated schema; adapter behavior has separate contracts"
            )]
            mod $module {
                include!(env!(concat!($prefix, "_", $suffix, "_SCHEMA")));
            }
        )+

        async fn create(
            database: &better_auth::seaorm::DatabaseConnection,
            name: &str,
        ) -> $crate::catalog::TestResult<[String; 2]> {
            use better_auth::seaorm::sea_orm::EntityName;

            match name {
                $(
                    $name => {
                        $module::create_auth_tables(database).await?;
                        Ok([
                            $module::user::Entity.table_name().to_owned(),
                            $module::session::Entity.table_name().to_owned(),
                        ])
                    }
                )+
                _ => Err(format!("Unknown User plugin catalog case {name}").into()),
            }
        }
    };
}

pub(crate) use generated_schemas;

pub fn cases(backend: &str) -> TestResult<Vec<Value>> {
    let fixture: Value = serde_json::from_str(&std::fs::read_to_string(format!(
        "{}/../../tests/fixtures/user-plugin-catalog-{backend}-1.7.6.json",
        env!("CARGO_MANIFEST_DIR"),
    ))?)?;
    assert_eq!(fixture["version"], "1.7.6");
    assert_eq!(fixture["database"], backend);
    let cases = fixture["cases"]
        .as_array()
        .ok_or("Missing User plugin catalog cases")?;
    assert_eq!(
        cases
            .iter()
            .map(|case| case["name"].as_str())
            .collect::<Vec<_>>(),
        [
            Some("default"),
            Some("reversed"),
            Some("mapped"),
            Some("empty-mappings"),
            Some("replaced"),
            Some("shared-columns"),
            Some("duplicate-plugins"),
        ],
        "Every captured configuration must be replayed in source order"
    );
    let configurations: Value =
        serde_json::from_str(include_str!("../../user-plugin-catalog-config.json"))?;
    let configurations = configurations
        .as_object()
        .ok_or("Missing User plugin catalog configurations")?;
    assert_eq!(cases.len(), configurations.len());
    for case in cases {
        let name = case["name"]
            .as_str()
            .ok_or("Missing User plugin catalog case name")?;
        let configuration = configurations
            .get(name)
            .ok_or("Missing generated User plugin configuration")?;
        assert_replay(
            &case["configuration"],
            &configuration["configuration"],
            &format!("{backend}/{name}/configuration"),
        );
        assert_replay(
            &case["plugins"],
            &configuration["plugins"],
            &format!("{backend}/{name}/plugins"),
        );
    }
    Ok(cases.clone())
}

pub async fn check(
    database: &DatabaseConnection,
    backend: DbBackend,
    case: &Value,
    tables: [String; 2],
) -> TestResult {
    let name = case["name"]
        .as_str()
        .ok_or("Missing User plugin catalog case name")?;
    let mut observed = Map::new();
    for (model, table) in ["user", "session"].into_iter().zip(&tables) {
        assert_eq!(
            Some(table.as_str()),
            case["declarations"][model]["value"]["modelName"].as_str(),
            "{backend:?}/{name}: the generated {model} table uses the resolved declaration"
        );
        let catalog = if backend == DbBackend::Sqlite {
            let (catalog, ddl) = sqlite_catalog::observe(
                database,
                table,
                "The generated User plugin table must exist",
            )
            .await?;
            assert_replay(
                &sqlite_catalog::ddl_declarations(&ddl)?,
                &sqlite_catalog::ddl_declarations(&case["ddl"][model])?,
                &format!("sqlite/{name}/ddl/{model}"),
            );
            eprintln!(
                "{}",
                json!({
                    "contract": "user-plugin-catalog",
                    "case": name,
                    "model": model,
                    "ddlSyntaxBoundary": "Complete SQLite catalog semantics and DDL objects are compared; original DDL spelling is retained without text equality",
                    "rustDdl": ddl,
                    "upstreamDdl": case["ddl"][model],
                })
            );
            catalog
        } else {
            server_catalog_indexes::observe(database, backend, table).await?
        };
        observed.insert(model.to_owned(), catalog);
    }
    if backend == DbBackend::Sqlite {
        assert_replay(
            &Value::Object(observed),
            &case["catalog"],
            &format!("sqlite/{name}/catalog"),
        );
    } else {
        assert_replay(
            &server_catalog_support::observe(database, backend, tables.clone()).await?,
            &case["columns"],
            &format!("{backend:?}/{name}/columns"),
        );
        assert_replay(
            &Value::Object(observed),
            &case["observation"],
            &format!("{backend:?}/{name}/observation"),
        );
        let migration = case["migration"]["initialSql"]
            .as_str()
            .ok_or("Missing frozen User plugin migration")?;
        for table in tables {
            server_catalog_support::assert_frozen_ddl(database, backend, &table, migration).await?;
        }
    }
    Ok(())
}
