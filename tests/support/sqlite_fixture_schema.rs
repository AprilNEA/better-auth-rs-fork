use better_auth_core::{AuthError, AuthResult};
use better_auth_seaorm::sea_orm::{
    ConnectionTrait, DatabaseConnection, DbBackend, DbErr, Statement,
};

fn db_error(error: DbErr) -> AuthError {
    AuthError::internal(error.to_string())
}

pub(crate) fn column_constraint(sql: &str, column: &str, constraint: &str) -> AuthResult<String> {
    let marker = format!("\"{column}\" ");
    let (prefix, tail) = sql
        .split_once(&marker)
        .ok_or_else(|| AuthError::internal(format!("Fixture column {column} is absent")))?;
    let (declaration, suffix) = tail
        .split_once(',')
        .ok_or_else(|| AuthError::internal("Fixture column must precede another declaration"))?;
    if declaration.contains("DEFAULT") {
        return Err(AuthError::internal(format!(
            "Fixture source column must have no default: {declaration}"
        )));
    }
    let declaration = declaration.replace(" NOT NULL", "");
    Ok(format!(
        "{prefix}{marker}{declaration}{constraint},{suffix}"
    ))
}

pub(crate) async fn rewrite_empty_table(
    database: &DatabaseConnection,
    table: &str,
    rewrite: impl FnOnce(&str) -> AuthResult<String>,
) -> AuthResult<()> {
    let catalog = database
        .query_all_raw(Statement::from_sql_and_values(
            DbBackend::Sqlite,
            "SELECT type, sql FROM sqlite_schema WHERE tbl_name = ? ORDER BY type, name",
            [table.into()],
        ))
        .await
        .map_err(db_error)?
        .into_iter()
        .map(|row| {
            Ok((
                row.try_get::<String>("", "type").map_err(db_error)?,
                row.try_get::<Option<String>>("", "sql").map_err(db_error)?,
            ))
        })
        .collect::<AuthResult<Vec<_>>>()?;
    let source = catalog
        .iter()
        .find(|(kind, _)| kind == "table")
        .and_then(|(_, sql)| sql.as_deref())
        .ok_or_else(|| AuthError::internal(format!("Fixture table {table} is absent")))?;
    let sql = rewrite(source)?;
    let table = table.replace('"', "\"\"");
    let count = database
        .query_one_raw(Statement::from_string(
            DbBackend::Sqlite,
            format!("SELECT COUNT(*) AS records FROM \"{table}\""),
        ))
        .await
        .map_err(db_error)?
        .ok_or_else(|| AuthError::internal("Fixture row count is absent"))?
        .try_get::<i64>("", "records")
        .map_err(db_error)?;
    if count != 0 {
        return Err(AuthError::internal(format!(
            "Fixture table {table} must be empty before schema changes"
        )));
    }
    for sql in [format!("DROP TABLE \"{table}\""), sql] {
        let _ = database
            .execute_raw(Statement::from_string(DbBackend::Sqlite, sql))
            .await
            .map_err(db_error)?;
    }
    for (_, sql) in catalog.into_iter().filter(|(kind, _)| kind != "table") {
        if let Some(sql) = sql {
            let _ = database
                .execute_raw(Statement::from_string(DbBackend::Sqlite, sql))
                .await
                .map_err(db_error)?;
        }
    }
    Ok(())
}
