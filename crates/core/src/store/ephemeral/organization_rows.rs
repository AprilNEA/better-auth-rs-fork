use super::rows::RowRef;
use super::table::TableRef;
use super::*;
use crate::store::schema::EntityRole;
use crate::user_fields::UserConfig;

pub(super) fn value(fields: &FieldMap, schema: &UserConfig, name: &str) -> Value {
    fields
        .get(schema.record_storage_key(name))
        .cloned()
        .unwrap_or_default()
}

pub(super) fn id(fields: &FieldMap) -> crate::SchemaValue<String> {
    crate::SchemaValue::from_field(fields.get("id").cloned().unwrap_or_default())
}

pub(super) fn field(row: &RowRef<FieldMap>, schema: &UserConfig, name: &str) -> AuthResult<Value> {
    Ok(row
        .field(schema.record_storage_key(name))?
        .unwrap_or_default())
}

pub(super) fn matches(row: &RowRef<FieldMap>, selectors: &[(String, Value)]) -> AuthResult<bool> {
    crate::memory_query::matches_all(selectors.iter(), |(name, expected)| {
        Ok(crate::query::field_matches_equality(
            &row.field(name)?.unwrap_or_default(),
            expected,
        ))
    })
}

pub(super) fn select_one(
    table: &TableRef<FieldMap>,
    selectors: &[(String, Value)],
) -> AuthResult<Option<RowRef<FieldMap>>> {
    Ok(table
        .select_refs(|row| matches(row, selectors))?
        .into_iter()
        .next())
}

#[cfg(test)]
pub(super) trait OrganizationRows {
    fn get_ref<Q: ?Sized>(&self, id: &Q) -> AuthResult<Option<RowRef<FieldMap>>>
    where
        crate::SchemaValue<String>: PartialEq<Q>;

    fn get<Q: ?Sized>(&self, id: &Q) -> AuthResult<Option<FieldMap>>
    where
        crate::SchemaValue<String>: PartialEq<Q>;
}

#[cfg(test)]
impl OrganizationRows for TableRef<FieldMap> {
    fn get_ref<Q: ?Sized>(&self, id: &Q) -> AuthResult<Option<RowRef<FieldMap>>>
    where
        crate::SchemaValue<String>: PartialEq<Q>,
    {
        Ok(self
            .select_refs(|row| {
                Ok(
                    crate::SchemaValue::<String>::from_field(row.field("id")?.unwrap_or_default())
                        == *id,
                )
            })?
            .into_iter()
            .next())
    }

    fn get<Q: ?Sized>(&self, id: &Q) -> AuthResult<Option<FieldMap>>
    where
        crate::SchemaValue<String>: PartialEq<Q>,
    {
        self.get_ref(id)?
            .map(|row| row.shallow_fields())
            .transpose()
    }
}

impl EphemeralStore {
    pub(super) fn insert_organization_row(
        &self,
        role: EntityRole,
        mut fields: FieldMap,
    ) -> AuthResult<RowRef<FieldMap>> {
        self.operation(|op| {
            let table = op.create_table(role)?;
            if let Some(id) = self.next_serial_id(table.len()?) {
                let _ = fields.insert("id".into(), id);
            }
            table.push(fields)
        })
    }

    pub(super) fn select_organization_rows(
        &self,
        role: EntityRole,
        selectors: &[(String, Value)],
    ) -> AuthResult<Vec<RowRef<FieldMap>>> {
        self.operation(|op| {
            op.capture_table(role)?
                .select_refs(|row| matches(row, selectors))
        })
    }

    pub(super) fn patch_organization_rows(
        &self,
        role: EntityRole,
        selectors: &[(String, Value)],
        patch: FieldMap,
        first_only: bool,
    ) -> AuthResult<Option<RowRef<FieldMap>>> {
        self.operation(|op| {
            let selected = op
                .capture_table(role)?
                .select_refs(|row| matches(row, selectors))?;
            let count = if first_only {
                selected.len().min(1)
            } else {
                selected.len()
            };
            for source in selected.iter().take(count) {
                source.apply_patch(patch.clone())?;
            }
            Ok(selected.into_iter().next())
        })
    }

    pub(super) fn delete_organization_rows(
        &self,
        role: EntityRole,
        selectors: &[(String, Value)],
    ) -> AuthResult<usize> {
        self.operation(|op| {
            let table = op.capture_table(role)?;
            let selected = table.select_refs(|row| matches(row, selectors))?;
            op.replace_table(role, table.without_refs(&selected)?)?;
            Ok(selected.len())
        })
    }
}
