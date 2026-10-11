//! A synchronous operation owns the database gate without exposing a data guard.

use super::rows::RowRef;
use super::table::TableRef;
use super::{EphemeralStore, State};
use crate::store::schema::EntityRole;
use crate::{AuthError, AuthResult, FieldMap, UserView};
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
        Ok(self.state()?.table(role)?.clone())
    }

    pub(super) fn capture_users(&self) -> AuthResult<TableRef<UserView>> {
        Ok(self.state()?.users.clone())
    }

    pub(super) fn replace_table(
        &self,
        role: EntityRole,
        replacement: TableRef<FieldMap>,
    ) -> AuthResult<()> {
        let previous = {
            let mut state = self.state()?;
            std::mem::replace(state.table_mut(role)?, replacement)
        };
        drop(previous);
        Ok(())
    }

    pub(super) fn replace_users(&self, replacement: TableRef<UserView>) -> AuthResult<()> {
        let previous = {
            let mut state = self.state()?;
            std::mem::replace(&mut state.users, replacement)
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
