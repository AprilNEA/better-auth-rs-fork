//! A synchronous operation owns the database gate without exposing a data guard.

use super::rows::RowRef;
use super::table::TableRef;
use super::{EphemeralStore, State};
use crate::store::schema::EntityRole;
use crate::{AuthError, AuthResult, FieldMap};
use parking_lot::ReentrantMutex;
use std::sync::{Arc, MutexGuard};

pub(super) type MemoryGate = Arc<ReentrantMutex<()>>;

pub(super) struct MemoryOperation<'a> {
    store: &'a EphemeralStore,
}

impl MemoryOperation<'_> {
    pub(super) fn run<T>(
        store: &EphemeralStore,
        action: impl FnOnce(&MemoryOperation<'_>) -> AuthResult<T>,
    ) -> AuthResult<T> {
        let _operation = store.operations.lock();
        action(&MemoryOperation { store })
    }

    fn state(&self) -> AuthResult<MutexGuard<'_, State>> {
        self.store
            .state
            .lock()
            .map_err(|_| AuthError::internal("Ephemeral state lock poisoned"))
    }

    pub(super) fn capture_table(&self, role: EntityRole) -> AuthResult<TableRef<FieldMap>> {
        self.capture_model_table(role, "Model")
    }

    pub(super) fn capture_join_table(&self, role: EntityRole) -> AuthResult<TableRef<FieldMap>> {
        self.capture_model_table(role, "JoinOption model")
    }

    fn capture_model_table(
        &self,
        role: EntityRole,
        context: &str,
    ) -> AuthResult<TableRef<FieldMap>> {
        let name = self.model_name(role)?;
        match self.capture_physical_table(&name)? {
            Some(table) => Ok(table),
            None => {
                let keys = serde_json::json!(self.root_keys()?);
                crate::observability::logger::current().error(
                    &format!("[MemoryAdapter] {context} {name} not found in the DB"),
                    &[crate::observability::LogArgument::Value(&keys)],
                );
                Err(AuthError::internal(format!("{context} {name} not found")))
            }
        }
    }

    pub(super) fn model_name(&self, role: EntityRole) -> AuthResult<String> {
        self.store.memory_model_name(role).map(str::to_owned)
    }

    pub(super) fn root_keys(&self) -> AuthResult<Vec<String>> {
        Ok(self.state()?.keys())
    }

    pub(super) fn capture_physical_table(
        &self,
        name: &str,
    ) -> AuthResult<Option<TableRef<FieldMap>>> {
        Ok(self.state()?.tables.get(name).cloned())
    }

    pub(super) fn table_or_empty(&self, name: &str) -> AuthResult<TableRef<FieldMap>> {
        Ok(self
            .capture_physical_table(name)?
            .unwrap_or_else(|| TableRef::new(self.store.operations.clone())))
    }

    pub(super) fn table_length(&self, role: EntityRole) -> AuthResult<usize> {
        self.capture_physical_table(&self.model_name(role)?)?
            .ok_or_else(|| {
                AuthError::type_error("Cannot read properties of undefined (reading 'length')")
            })?
            .len()
    }

    pub(super) fn create_table(&self, role: EntityRole) -> AuthResult<TableRef<FieldMap>> {
        if matches!(
            self.store.config.advanced.database.generate_id(),
            crate::id::IdGeneration::Serial
        ) {
            let _ = self.table_length(role)?;
        }
        let name = self.model_name(role)?;
        Ok(self
            .state()?
            .tables
            .entry(name)
            .or_insert_with(|| TableRef::new(self.store.operations.clone()))
            .clone())
    }

    pub(super) fn replace_table(
        &self,
        role: EntityRole,
        replacement: TableRef<FieldMap>,
    ) -> AuthResult<()> {
        self.replace_physical_table(self.model_name(role)?, Some(replacement))
    }

    pub(super) fn replace_physical_table(
        &self,
        name: String,
        replacement: Option<TableRef<FieldMap>>,
    ) -> AuthResult<()> {
        let previous = match replacement {
            Some(table) => self.state()?.tables.insert(name, table),
            None => self.state()?.tables.shift_remove(&name),
        };
        drop(previous);
        Ok(())
    }

    pub(super) fn capture_state(&self) -> AuthResult<State> {
        Ok(self.state()?.clone())
    }

    pub(super) fn shallow_snapshot(&self) -> AuthResult<State> {
        self.capture_state()?.shallow_snapshot()
    }

    pub(super) fn structured_clone(
        &self,
        context: &mut crate::StructuredCloneContext,
    ) -> AuthResult<State> {
        self.structured_clone_with_device_origins(context, |_, _, _| {})
    }

    pub(super) fn structured_clone_with_device_origins(
        &self,
        context: &mut crate::StructuredCloneContext,
        device_origin: impl FnMut(RowRef<FieldMap>, RowRef<FieldMap>, FieldMap),
    ) -> AuthResult<State> {
        State::structured_clone_from(self, context, device_origin)
    }
}
