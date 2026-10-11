//! Captured arrays retain their identity when an operation replaces an active table.

use super::operation::MemoryGate;
use super::rows::{RowRef, TransactionId, TransactionRow, row_json};
use crate::{AuthError, AuthRecordFields, AuthResult, FromFieldMap, StructuredCloneContext};
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};

type RowArray<T> = Vec<Arc<Mutex<T>>>;

pub(super) struct TableRef<T> {
    rows: Arc<Mutex<RowArray<T>>>,
    gate: MemoryGate,
}

pub(super) struct ReconcilePlan<T> {
    changed: Vec<(RowRef<T>, Option<RowRef<T>>)>,
    appended: Vec<RowRef<T>>,
}

impl<T> ReconcilePlan<T> {
    pub(super) fn is_empty(&self) -> bool {
        self.changed.is_empty() && self.appended.is_empty()
    }

    pub(super) fn apply(&self, latest: &TableRef<T>) -> AuthResult<TableRef<T>> {
        let _operation = latest.gate.lock();
        if self.is_empty() {
            return Ok(latest.clone());
        }
        let mut rows = Vec::new();
        for row in latest.snapshot_refs()? {
            match self
                .changed
                .iter()
                .find(|(original, _)| row.same_row(original))
            {
                Some((_, Some(replacement))) => rows.push(replacement.clone()),
                Some((_, None)) => {}
                None => rows.push(row),
            }
        }
        rows.extend(self.appended.iter().cloned());
        Ok(TableRef::from_refs(latest.gate.clone(), rows))
    }
}

impl<T> Clone for TableRef<T> {
    fn clone(&self) -> Self {
        Self {
            rows: self.rows.clone(),
            gate: self.gate.clone(),
        }
    }
}

impl<T> TableRef<T> {
    pub(super) fn new(gate: MemoryGate) -> Self {
        Self {
            gate,
            rows: Arc::default(),
        }
    }

    pub(super) fn from_refs(gate: MemoryGate, rows: Vec<RowRef<T>>) -> Self {
        Self {
            rows: Arc::new(Mutex::new(rows.into_iter().map(|row| row.0).collect())),
            gate,
        }
    }

    fn lock(&self) -> AuthResult<std::sync::MutexGuard<'_, RowArray<T>>> {
        self.rows
            .lock()
            .map_err(|_| AuthError::internal("Ephemeral table lock poisoned"))
    }

    pub(super) fn len(&self) -> AuthResult<usize> {
        let _operation = self.gate.lock();
        Ok(self.lock()?.len())
    }

    pub(super) fn row_at(&self, index: usize) -> AuthResult<Option<RowRef<T>>> {
        let _operation = self.gate.lock();
        Ok(self
            .lock()?
            .get(index)
            .map(|row| RowRef(row.clone(), self.gate.clone())))
    }

    pub(super) fn snapshot_refs(&self) -> AuthResult<Vec<RowRef<T>>> {
        let _operation = self.gate.lock();
        Ok(self
            .lock()?
            .iter()
            .map(|row| RowRef(row.clone(), self.gate.clone()))
            .collect())
    }

    pub(super) fn shallow_copy(&self) -> AuthResult<Self> {
        Ok(Self::from_refs(self.gate.clone(), self.snapshot_refs()?))
    }

    pub(super) fn push(&self, value: T) -> AuthResult<RowRef<T>> {
        let _operation = self.gate.lock();
        let row = Arc::new(Mutex::new(value));
        self.lock()?.push(row.clone());
        Ok(RowRef(row, self.gate.clone()))
    }

    pub(super) fn contains_ref(&self, source: &RowRef<T>) -> AuthResult<bool> {
        let _operation = self.gate.lock();
        Ok(self.lock()?.iter().any(|row| Arc::ptr_eq(row, &source.0)))
    }

    pub(super) fn select_refs(
        &self,
        mut predicate: impl FnMut(&RowRef<T>) -> AuthResult<bool>,
    ) -> AuthResult<Vec<RowRef<T>>> {
        let _operation = self.gate.lock();
        let length = self.len()?;
        let mut selected = Vec::new();
        for index in 0..length {
            if let Some(row) = self.row_at(index)?
                && predicate(&row)?
            {
                selected.push(row);
            }
        }
        Ok(selected)
    }

    pub(super) fn without_refs(&self, selected: &[RowRef<T>]) -> AuthResult<Self> {
        let _operation = self.gate.lock();
        let rows =
            self.select_refs(|row| Ok(!selected.iter().any(|selected| row.same_row(selected))))?;
        Ok(Self::from_refs(self.gate.clone(), rows))
    }
}

impl<T: Clone> TableRef<T> {
    pub(super) fn snapshot(&self) -> AuthResult<Vec<T>> {
        let _operation = self.gate.lock();
        self.snapshot_refs()?.iter().map(RowRef::snapshot).collect()
    }
}

impl<T: Clone + AuthRecordFields + FromFieldMap> TableRef<T> {
    pub(super) fn deep_clone(&self, context: &mut StructuredCloneContext) -> AuthResult<Self> {
        self.deep_clone_with(context, |_, _, _| {})
    }

    pub(super) fn deep_clone_with(
        &self,
        context: &mut StructuredCloneContext,
        mut cloned_row: impl FnMut(RowRef<T>, RowRef<T>, T),
    ) -> AuthResult<Self> {
        let _operation = self.gate.lock();
        let cloned = Self::new(self.gate.clone());
        let length = self.len()?;
        for index in 0..length {
            if let Some(source) = self.row_at(index)? {
                let before = source.snapshot()?;
                let row = before.structured_clone(context)?;
                let target = cloned.push(row)?;
                cloned_row(source, target, before);
            }
        }
        Ok(cloned)
    }
}

impl<T: Clone + AuthRecordFields + TransactionRow> TableRef<T> {
    pub(super) fn reconcile(&self, base: &Self, working: &Self) -> AuthResult<Self> {
        self.reconcile_with_plan(base, working)
            .map(|(table, _)| table)
    }

    #[expect(
        clippy::mutable_key_type,
        reason = "TransactionId hashes and compares mutable objects by stable identity, never by their mutable fields."
    )]
    pub(super) fn reconcile_with_plan(
        &self,
        base: &Self,
        working: &Self,
    ) -> AuthResult<(Self, ReconcilePlan<T>)> {
        let _operation = self.gate.lock();
        let index = |table: &Self| -> AuthResult<HashMap<TransactionId, RowRef<T>>> {
            let mut indexed = HashMap::new();
            let mut position = 0;
            while position < table.len()? {
                if let Some(row) = table.row_at(position)? {
                    let id = TransactionId(row.snapshot()?.transaction_id());
                    let _ = indexed.insert(id, row);
                }
                position += 1;
            }
            Ok(indexed)
        };
        let base_by_id = index(base)?;
        let working_by_id = index(working)?;
        let mut placed = HashSet::new();
        let mut merged = Vec::new();
        let mut plan = ReconcilePlan {
            changed: Vec::new(),
            appended: Vec::new(),
        };
        let mut position = 0;
        while position < self.len()? {
            if let Some(live) = self.row_at(position)? {
                let id = TransactionId(live.snapshot()?.transaction_id());
                let original = base_by_id.get(&id);
                let changed = working_by_id.get(&id);
                if original.is_some() && changed.is_none() {
                    plan.changed.push((live, None));
                    position += 1;
                    continue;
                }
                let replacement = match (original, changed) {
                    (None, Some(changed)) => {
                        plan.changed.push((live, Some(changed.clone())));
                        changed.clone()
                    }
                    (Some(original), Some(changed)) => {
                        let before = row_json(&original.snapshot()?)?;
                        let after = row_json(&changed.snapshot()?)?;
                        if before != after {
                            plan.changed.push((live, Some(changed.clone())));
                            changed.clone()
                        } else {
                            live
                        }
                    }
                    (_, None) => live,
                };
                merged.push(replacement);
                let _ = placed.insert(id);
            }
            position += 1;
        }
        let mut position = 0;
        while position < working.len()? {
            if let Some(row) = working.row_at(position)? {
                let id = TransactionId(row.snapshot()?.transaction_id());
                if !base_by_id.contains_key(&id) && !placed.contains(&id) {
                    plan.appended.push(row.clone());
                    merged.push(row);
                }
            }
            position += 1;
        }
        Ok((Self::from_refs(self.gate.clone(), merged), plan))
    }
}

#[cfg(test)]
#[path = "table_tests.rs"]
mod tests;
