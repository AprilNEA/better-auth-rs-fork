use super::*;

async fn rows(database: &DatabaseConnection, sql: String) -> Vec<Value> {
    database
        .query_all_raw(Statement::from_string(database.get_database_backend(), sql))
        .await
        .unwrap()
        .into_iter()
        .map(|row| serde_json::from_str(&row.try_get::<String>("", "value").unwrap()).unwrap())
        .collect()
}

pub(super) async fn catalog(database: &DatabaseConnection) -> Vec<Value> {
    rows(database, "SELECT json_object('type', type, 'name', name, 'table', tbl_name, 'sql', sql) AS value FROM sqlite_schema ORDER BY type, name".into()).await
}

pub(super) async fn snapshot(database: &DatabaseConnection) -> Snapshot {
    let mut snapshot = BTreeMap::new();
    for table in catalog(database)
        .await
        .into_iter()
        .filter(|row| row["type"] == "table")
    {
        let table = table["name"].as_str().unwrap();
        let columns = database
            .query_all_raw(Statement::from_string(
                database.get_database_backend(),
                format!("PRAGMA table_info(\"{table}\")"),
            ))
            .await
            .unwrap();
        let columns = columns
            .iter()
            .map(|row| {
                let column = row.try_get::<String>("", "name").unwrap();
                format!("'{column}',\"{column}\"")
            })
            .collect::<Vec<_>>()
            .join(",");
        let values = rows(
            database,
            format!("SELECT json_object({columns}) AS value FROM \"{table}\" ORDER BY rowid"),
        )
        .await;
        let _ = snapshot.insert(table.into(), values);
    }
    snapshot
}

fn column_constraint(sql: &str, column: &str, constraint: &str) -> String {
    let marker = format!("\"{column}\" ");
    let (prefix, tail) = sql.split_once(&marker).unwrap();
    let (declaration, suffix) = tail.split_once(',').unwrap();
    assert!(
        !declaration.contains("DEFAULT"),
        "Fixture source column must have no default: {declaration}"
    );
    let declaration = declaration.replace(" NOT NULL", "");
    format!("{prefix}{marker}{declaration}{constraint},{suffix}")
}

pub(super) async fn prepare(database: &DatabaseConnection, model: Model, old: OldColumn) {
    let before = snapshot(database).await;
    let (table, _, _, column) = model.mapping();
    assert!(before[table].is_empty());
    let mut expected_catalog = catalog(database).await;
    let entry = expected_catalog
        .iter_mut()
        .find(|entry| entry["type"] == "table" && entry["name"] == table)
        .unwrap();
    let constraint = match old {
        OldColumn::Required => " NOT NULL",
        OldColumn::Nullable => "",
        OldColumn::Defaulted => " NOT NULL DEFAULT 'legacy-default'",
    };
    let mut sql = column_constraint(entry["sql"].as_str().unwrap(), column, constraint);
    if matches!(model, Model::Passkey) {
        // The native record API omits the bundled Rust credential and update timestamp.
        sql = column_constraint(&sql, "credential", " NOT NULL DEFAULT 'legacy-credential'");
        sql = column_constraint(
            &sql,
            "updated_at",
            " NOT NULL DEFAULT '2030-01-01T00:00:00.000Z'",
        );
    }
    entry["sql"] = json!(sql);
    execute(database, &format!("DROP TABLE \"{table}\"")).await;
    execute(database, &sql).await;
    for entry in expected_catalog
        .iter()
        .filter(|entry| entry["table"] == table && entry["type"] != "table")
    {
        if let Some(sql) = entry["sql"].as_str() {
            execute(database, sql).await;
        }
    }
    assert_eq!(catalog(database).await, expected_catalog);
    assert_eq!(snapshot(database).await, before);
}

pub(super) async fn seed(database: &DatabaseConnection, model: Model) {
    if matches!(model, Model::Session | Model::Account | Model::Passkey) {
        execute(database, &format!("INSERT INTO users (id, name, email, email_verified, image, created_at, updated_at) VALUES ('owner', 'Owner', 'owner@schema-preflight.test', 1, NULL, '{DATE}', '{DATE}')")).await;
    }
    if matches!(model, Model::Team) {
        execute(database, &format!("INSERT INTO organization (id, name, slug, logo, metadata, created_at, updated_at) VALUES ('legacy-default', 'Legacy', 'legacy-default', NULL, NULL, '{DATE}', '{DATE}')")).await;
    }
}
