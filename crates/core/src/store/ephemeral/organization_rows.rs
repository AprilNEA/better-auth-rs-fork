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

pub(super) fn view<T: FromFieldMap>(fields: &FieldMap, schema: &UserConfig) -> AuthResult<T> {
    let mut logical: FieldMap = schema
        .fields()
        .keys()
        .map(|name| (name.clone(), value(fields, schema, name)))
        .collect();
    if let Some(id) = fields.get("id") {
        let _ = logical.insert("id".into(), id.clone());
    }
    T::from_field_values(logical)
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

/// Organization tables store physical fields. Typed values are read-only business views.
pub(super) trait OrganizationRows {
    fn get_ref<Q: ?Sized>(&self, id: &Q) -> AuthResult<Option<RowRef<FieldMap>>>
    where
        crate::SchemaValue<String>: PartialEq<Q>;

    fn get<Q: ?Sized>(&self, id: &Q) -> AuthResult<Option<FieldMap>>
    where
        crate::SchemaValue<String>: PartialEq<Q>;

    fn replace<Q: ?Sized>(&self, id: &Q, fields: FieldMap) -> AuthResult<bool>
    where
        crate::SchemaValue<String>: PartialEq<Q>;

    fn remove<Q: ?Sized>(&mut self, id: &Q) -> AuthResult<Option<FieldMap>>
    where
        crate::SchemaValue<String>: PartialEq<Q>;
}

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

    fn replace<Q: ?Sized>(&self, id: &Q, fields: FieldMap) -> AuthResult<bool>
    where
        crate::SchemaValue<String>: PartialEq<Q>,
    {
        if let Some(row) = self.get_ref(id)? {
            row.replace(fields)?;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    fn remove<Q: ?Sized>(&mut self, id: &Q) -> AuthResult<Option<FieldMap>>
    where
        crate::SchemaValue<String>: PartialEq<Q>,
    {
        let Some(row) = self.get_ref(id)? else {
            return Ok(None);
        };
        let fields = row.shallow_fields()?;
        *self = self.without_refs(std::slice::from_ref(&row))?;
        Ok(Some(fields))
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
