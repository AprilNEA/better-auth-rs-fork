//! The physical root owns ordered table bindings. Captured arrays retain their identities.

use super::operation::{MemoryGate, MemoryOperation};
use super::rows::RowRef;
use super::table::TableRef;
use crate::{AuthError, AuthResult, FieldMap};
use indexmap::IndexMap;

/// Clone captures bindings. A shallow snapshot copies arrays while retaining row identities.
#[derive(Clone, Default)]
pub(super) struct State {
    pub(super) tables: IndexMap<String, TableRef<FieldMap>>,
}

impl State {
    pub(super) fn with_models<'a>(
        gate: MemoryGate,
        names: impl IntoIterator<Item = &'a str>,
    ) -> Self {
        Self {
            tables: names
                .into_iter()
                .map(|name| (name.to_owned(), TableRef::new(gate.clone())))
                .collect(),
        }
    }

    pub(super) fn keys(&self) -> Vec<String> {
        let mut keys: Vec<_> = self.tables.keys().cloned().collect();
        keys.sort_by_key(|name| {
            crate::utils::json::array_index(name).map_or((true, 0), |index| (false, index))
        });
        keys
    }

    pub(super) fn table(&self, name: &str) -> AuthResult<&TableRef<FieldMap>> {
        self.tables
            .get(name)
            .ok_or_else(|| AuthError::internal(format!("Model {name} not found")))
    }

    #[cfg(test)]
    #[expect(
        clippy::expect_used,
        reason = "These fixture observations require a table explicitly supplied by test setup."
    )]
    pub(super) fn fixture_table(&self, name: &str) -> &TableRef<FieldMap> {
        self.tables
            .get(name)
            .expect("Expected a declared fixture table")
    }

    pub(super) fn shallow_snapshot(&self) -> AuthResult<Self> {
        let mut tables = IndexMap::new();
        let mut copies = Vec::<(crate::FieldArray, TableRef<FieldMap>)>::new();
        for name in self.keys() {
            let table = self.table(&name)?;
            let array = table.array();
            let copy = match copies.iter().find(|(source, _)| source.same_array(&array)) {
                Some((_, copy)) => copy.clone(),
                None => {
                    let copy = table.shallow_copy()?;
                    copies.push((array, copy.clone()));
                    copy
                }
            };
            let _ = tables.insert(name, copy);
        }
        Ok(Self { tables })
    }

    pub(super) fn structured_clone_from(
        operation: &MemoryOperation<'_>,
        context: &mut crate::StructuredCloneContext,
        mut device_origin: impl FnMut(RowRef<FieldMap>, RowRef<FieldMap>, FieldMap),
    ) -> AuthResult<Self> {
        let keys = operation.root_keys()?;
        let device_model = operation.model_name(crate::store::schema::EntityRole::DeviceCode)?;
        let mut tables = IndexMap::new();
        for name in keys {
            // A preceding field getter may replace or delete a later root binding.
            let Some(table) = operation.capture_physical_table(&name)? else {
                continue;
            };
            let cloned = if name == device_model {
                table.deep_clone_with(context, &mut device_origin)?
            } else {
                table.deep_clone(context)?
            };
            let _ = tables.insert(name, cloned);
        }
        Ok(Self { tables })
    }
}
