use super::{
    FieldValue,
    structured_clone::{ArrayCloneSeed, CloneWrite},
};
use crate::AuthResult;
use parking_lot::Mutex;
use std::{
    any::Any,
    cell::RefCell,
    collections::{BTreeMap, HashSet},
    fmt,
    sync::Arc,
};

/// A stable array handle. Live arrays read each index from their current source.
/// Use `snapshot` only when an independent list of shallow values is required.
/// `PartialEq` compares owned arrays structurally and live arrays by identity.
/// Elements retain strong handles. Cycles retain their memory; this handle has no tracing garbage collection.
/// Live arrays remain dynamic during infallible schema decoding so fallible getters retain their original errors.
#[derive(Clone)]
pub struct FieldArray(ArrayStorage);

#[derive(Clone)]
enum ArrayStorage {
    // Native restoration can inspect a prepared clone before success commits the array or failure resets the array.
    Owned(Arc<Mutex<Option<ArrayValues>>>),
    Live(Arc<dyn FieldArraySource>),
}

#[derive(Clone)]
struct ArrayValues {
    length: usize,
    entries: BTreeMap<usize, FieldValue>,
}

pub(crate) trait FieldArraySource: Send + Sync {
    fn len(&self) -> AuthResult<usize>;
    fn own_indices(&self) -> AuthResult<Vec<usize>>;
    fn get(&self, index: usize) -> AuthResult<Option<FieldValue>>;
    fn identity(&self) -> usize;
    fn clone_seed(&self) -> AuthResult<Option<ArrayCloneSeed>> {
        Ok(None)
    }
    fn as_any(&self) -> Option<&dyn Any> {
        None
    }
}

#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
pub(crate) enum ArrayIdentity {
    Owned(usize),
    Live(usize),
}

impl FieldArray {
    /// Create an empty array with a distinct identity.
    pub fn new() -> Self {
        Vec::new().into()
    }

    pub(crate) fn from_source(source: Arc<dyn FieldArraySource>) -> Self {
        Self(ArrayStorage::Live(source))
    }

    /// Read the current array length, including missing indices.
    pub fn len(&self) -> AuthResult<usize> {
        match &self.0 {
            ArrayStorage::Owned(values) => {
                Ok(values.lock().as_ref().map_or(0, |values| values.length))
            }
            ArrayStorage::Live(source) => source.len(),
        }
    }

    /// Return whether the current array length is zero.
    pub fn is_empty(&self) -> AuthResult<bool> {
        Ok(self.len()? == 0)
    }

    /// Read one current index. `None` is a hole or an index outside the array.
    pub fn get(&self, index: usize) -> AuthResult<Option<FieldValue>> {
        match &self.0 {
            ArrayStorage::Owned(values) => Ok(values
                .lock()
                .as_ref()
                .and_then(|values| values.entries.get(&index))
                .cloned()),
            ArrayStorage::Live(source) => source.get(index),
        }
    }

    /// Read the first index without reading later values.
    pub fn first(&self) -> AuthResult<Option<FieldValue>> {
        self.get(0)
    }

    /// Capture present indices in numeric order without evaluating their values.
    pub fn own_indices(&self) -> AuthResult<Vec<usize>> {
        let mut indices = match &self.0 {
            ArrayStorage::Owned(values) => values
                .lock()
                .as_ref()
                .map_or_else(Vec::new, |values| values.entries.keys().copied().collect()),
            ArrayStorage::Live(source) => source.own_indices()?,
        };
        indices.sort_unstable();
        Ok(indices)
    }

    /// Capture the length, then read indices lazily. Missing indices yield `Undefined`.
    pub fn iter(&self) -> AuthResult<FieldArrayIter> {
        Ok(FieldArrayIter {
            array: self.clone(),
            next: 0,
            length: self.len()?,
        })
    }

    /// Copy the current indexed values. Missing indices become `Undefined` in this dense list.
    pub fn snapshot(&self) -> AuthResult<Vec<FieldValue>> {
        self.iter()?.collect()
    }

    /// Test membership with JavaScript SameValueZero, including undefined for missing indices.
    pub fn includes(&self, expected: &FieldValue) -> AuthResult<bool> {
        for value in self.iter()? {
            if value?.same_value_zero(expected) {
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// Test present indices in order, stopping at the first false result or error.
    /// Missing indices are skipped, as in JavaScript `Array.prototype.every`.
    pub fn every(
        &self,
        mut predicate: impl FnMut(&FieldValue) -> AuthResult<bool>,
    ) -> AuthResult<bool> {
        let length = self.len()?;
        for index in 0..length {
            if let Some(value) = self.get(index)?
                && !predicate(&value)?
            {
                return Ok(false);
            }
        }
        Ok(true)
    }

    /// Map present indices in order, preserving missing indices and the captured length.
    pub fn map(
        &self,
        mut transform: impl FnMut(FieldValue) -> AuthResult<FieldValue>,
    ) -> AuthResult<Self> {
        let length = self.len()?;
        let mut entries = BTreeMap::new();
        for index in 0..length {
            if let Some(value) = self.get(index)? {
                let _ = entries.insert(index, transform(value)?);
            }
        }
        Ok(Self(ArrayStorage::Owned(Arc::new(Mutex::new(Some(
            ArrayValues { length, entries },
        ))))))
    }

    /// Filter present indices in order, omitting missing indices from the new dense array.
    pub fn filter(
        &self,
        mut predicate: impl FnMut(&FieldValue) -> AuthResult<bool>,
    ) -> AuthResult<Self> {
        let length = self.len()?;
        let mut values = Vec::new();
        for index in 0..length {
            if let Some(value) = self.get(index)?
                && predicate(&value)?
            {
                values.push(value);
            }
        }
        Ok(values.into())
    }

    /// Compare array identity without reading indices.
    pub fn same_array(&self, other: &Self) -> bool {
        self.identity() == other.identity()
    }

    pub(crate) fn identity(&self) -> ArrayIdentity {
        match &self.0 {
            ArrayStorage::Owned(values) => ArrayIdentity::Owned(Arc::as_ptr(values) as usize),
            ArrayStorage::Live(source) => ArrayIdentity::Live(source.identity()),
        }
    }

    pub(crate) fn source<T: 'static>(&self) -> Option<&T> {
        match &self.0 {
            ArrayStorage::Live(source) => source.as_any()?.downcast_ref(),
            ArrayStorage::Owned(_) => None,
        }
    }

    // Infallible typed narrowing must preserve holes and must not evaluate fallible live getters.
    pub(crate) fn owned_values(&self) -> Option<Vec<FieldValue>> {
        let ArrayStorage::Owned(values) = &self.0 else {
            return None;
        };
        let values = values.lock();
        let values = values.as_ref()?;
        if values.entries.len() != values.length {
            return None;
        }
        Some(
            (0..values.length)
                .map(|index| values.entries.get(&index).cloned().unwrap_or_default())
                .collect(),
        )
    }

    pub(crate) fn clone_seed(&self) -> AuthResult<ArrayCloneSeed> {
        if let ArrayStorage::Live(source) = &self.0
            && let Some(seed) = source.clone_seed()?
        {
            return Ok(seed);
        }
        let target = Arc::new(Mutex::new(None));
        Ok(ArrayCloneSeed {
            array: Self(ArrayStorage::Owned(target.clone())),
            prepare: Box::new(move |length, entries| {
                let length = entries
                    .iter()
                    .map(|(index, _)| index + 1)
                    .fold(length, usize::max);
                let mut values = Some(ArrayValues {
                    length,
                    entries: entries.into_iter().collect(),
                });
                Ok(CloneWrite::new(move || {
                    std::mem::swap(&mut *target.lock(), &mut values);
                }))
            }),
        })
    }
}

impl Default for FieldArray {
    fn default() -> Self {
        Self::new()
    }
}

impl From<Vec<FieldValue>> for FieldArray {
    fn from(values: Vec<FieldValue>) -> Self {
        Self(ArrayStorage::Owned(Arc::new(Mutex::new(Some(
            ArrayValues {
                length: values.len(),
                entries: values.into_iter().enumerate().collect(),
            },
        )))))
    }
}

impl FromIterator<FieldValue> for FieldArray {
    fn from_iter<T: IntoIterator<Item = FieldValue>>(values: T) -> Self {
        values.into_iter().collect::<Vec<_>>().into()
    }
}

/// A fallible array iterator that retains the source identity and captures its initial length.
pub struct FieldArrayIter {
    array: FieldArray,
    next: usize,
    length: usize,
}

impl Iterator for FieldArrayIter {
    type Item = AuthResult<FieldValue>;
    fn next(&mut self) -> Option<Self::Item> {
        if self.next >= self.length {
            return None;
        }
        let index = self.next;
        self.next += 1;
        Some(self.array.get(index).map(Option::unwrap_or_default))
    }
    fn size_hint(&self) -> (usize, Option<usize>) {
        let remaining = self.length - self.next;
        (remaining, Some(remaining))
    }
}

impl ExactSizeIterator for FieldArrayIter {}

thread_local! {
    static COMPARING: RefCell<HashSet<(ArrayIdentity, ArrayIdentity)>> = RefCell::new(HashSet::new());
    static FORMATTING: RefCell<HashSet<ArrayIdentity>> = RefCell::new(HashSet::new());
}

impl PartialEq for FieldArray {
    fn eq(&self, other: &Self) -> bool {
        match (&self.0, &other.0) {
            (ArrayStorage::Owned(left), ArrayStorage::Owned(right)) => {
                let identity = (self.identity(), other.identity());
                let Some(_guard) = ComparisonGuard::enter(identity) else {
                    return true;
                };
                // Recursive comparisons must not retain either array lock.
                let left = left.lock().clone();
                let right = right.lock().clone();
                match (left, right) {
                    (Some(left), Some(right)) => {
                        left.length == right.length && left.entries == right.entries
                    }
                    (None, None) => true,
                    _ => false,
                }
            }
            _ => self.same_array(other),
        }
    }
}

impl fmt::Debug for FieldArray {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.0 {
            ArrayStorage::Owned(values) => {
                let identity = self.identity();
                let Some(_guard) = FormattingGuard::enter(identity) else {
                    return formatter.write_str("[Circular]");
                };
                let values = values.lock().clone();
                formatter
                    .debug_struct("Array")
                    .field("length", &values.as_ref().map_or(0, |values| values.length))
                    .field("entries", &values.as_ref().map(|values| &values.entries))
                    .finish()
            }
            ArrayStorage::Live(_) => formatter
                .debug_struct("LiveArray")
                .field("identity", &self.identity())
                .finish(),
        }
    }
}

struct ComparisonGuard((ArrayIdentity, ArrayIdentity));
impl ComparisonGuard {
    fn enter(identity: (ArrayIdentity, ArrayIdentity)) -> Option<Self> {
        COMPARING
            .with(|active| active.borrow_mut().insert(identity))
            .then(|| Self(identity))
    }
}
impl Drop for ComparisonGuard {
    fn drop(&mut self) {
        COMPARING.with(|active| {
            let _ = active.borrow_mut().remove(&self.0);
        });
    }
}
struct FormattingGuard(ArrayIdentity);
impl FormattingGuard {
    fn enter(identity: ArrayIdentity) -> Option<Self> {
        FORMATTING
            .with(|active| active.borrow_mut().insert(identity))
            .then(|| Self(identity))
    }
}
impl Drop for FormattingGuard {
    fn drop(&mut self) {
        FORMATTING.with(|active| {
            let _ = active.borrow_mut().remove(&self.0);
        });
    }
}

#[cfg(test)]
#[path = "array_tests.rs"]
mod tests;
