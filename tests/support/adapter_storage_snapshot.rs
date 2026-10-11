use better_auth_core::{
    AuthError, AuthResult, FieldMap, FieldValue,
    store::{EphemeralStore, schema::EntityRole},
};
use better_auth_seaorm::sea_orm::{ConnectionTrait, DatabaseConnection, DbBackend, Statement};
use std::collections::BTreeMap;

pub(super) enum Storage {
    Memory(Box<EphemeralStore>),
    Sqlite(DatabaseConnection),
}

impl Storage {
    pub(super) async fn snapshot(
        &self,
        tables: &[(&str, &str, EntityRole)],
    ) -> AuthResult<BTreeMap<String, Vec<FieldMap>>> {
        let mut snapshot = BTreeMap::new();
        for &(name, table, role) in tables {
            let mut rows = match self {
                Self::Memory(store) => store.storage_rows(role)?,
                Self::Sqlite(database) => {
                    let columns = database
                        .query_all_raw(Statement::from_string(
                            DbBackend::Sqlite,
                            format!("PRAGMA table_info(\"{table}\")"),
                        ))
                        .await
                        .map_err(|error| AuthError::internal(error.to_string()))?;
                    let columns = columns
                        .iter()
                        .map(|row| row.try_get::<String>("", "name"))
                        .collect::<Result<Vec<_>, _>>()
                        .map_err(|error| AuthError::internal(error.to_string()))?;
                    let columns = columns
                        .iter()
                        .map(|name| format!("'{name}',\"{name}\""))
                        .collect::<Vec<_>>()
                        .join(",");
                    database.query_all_raw(Statement::from_string(DbBackend::Sqlite,
                        format!("SELECT json_object({columns}) AS value FROM \"{table}\" ORDER BY id"),
                    )).await.map_err(|error| AuthError::internal(error.to_string()))?
                        .into_iter().map(|row| {
                            let json = row.try_get::<String>("", "value")
                                .map_err(|error| AuthError::internal(error.to_string()))?;
                            FieldMap::from_json(serde_json::from_str(&json)?)
                        }).collect::<AuthResult<Vec<_>>>()?
                }
            };
            rows.sort_by(|left, right| {
                left.get("id")
                    .and_then(FieldValue::as_str)
                    .cmp(&right.get("id").and_then(FieldValue::as_str))
            });
            let _ = snapshot.insert(name.into(), rows);
        }
        Ok(snapshot)
    }
}
