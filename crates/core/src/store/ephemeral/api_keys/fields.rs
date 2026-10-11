use super::*;
use crate::FromFieldMap;

impl EphemeralStore {
    pub(super) async fn project_api_key_refs(
        &self,
        rows: Vec<RowRef<crate::FieldMap>>,
    ) -> AuthResult<Vec<ApiKey>> {
        self.project_plugin_refs(EntityRole::ApiKey, rows)
            .await?
            .into_iter()
            .map(ApiKey::from_field_values)
            .collect()
    }

    pub(super) async fn find_api_key(
        &self,
        predicate: impl Fn(&crate::FieldMap) -> bool + Send,
    ) -> AuthResult<Option<ApiKey>> {
        let selected = self
            .raw("apikey", "findOne", move |op| {
                Ok(op
                    .capture_table(EntityRole::ApiKey)?
                    .select_refs(|row| Ok(predicate(&row.shallow_fields()?)))?
                    .into_iter()
                    .next())
            })
            .await?;
        Ok(self
            .project_api_key_refs(selected.into_iter().collect())
            .await?
            .pop())
    }
}
