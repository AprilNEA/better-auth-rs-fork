use super::{FieldMap, FieldValue};
use crate::{AuthError, AuthResult};
use std::{
    cell::RefCell,
    collections::HashSet,
    fmt,
    sync::{Arc, Mutex},
};

/// A stable object handle. Property reads retain child handles and observe the current source.
/// Owned objects compare structurally. Live objects compare source identity without reading the source.
/// Object properties retain strong handles. Cycles retain their memory until a property is deleted
/// to break the cycle; this handle does not provide tracing garbage collection.
#[derive(Clone)]
pub struct FieldObject(ObjectStorage);

#[derive(Clone)]
enum ObjectStorage {
    Owned(Arc<Mutex<FieldMap>>),
    Live(Arc<dyn FieldObjectSource>),
}

pub(crate) trait FieldObjectSource: Send + Sync {
    fn get(&self, name: &str) -> AuthResult<Option<FieldValue>>;
    fn set(&self, name: String, value: FieldValue) -> AuthResult<Option<FieldValue>>;
    fn delete(&self, name: &str) -> AuthResult<Option<FieldValue>>;
    fn snapshot_fields(&self) -> AuthResult<FieldMap>;
    fn identity(&self) -> usize;
}

#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
pub(crate) enum ObjectIdentity {
    Owned(usize),
    Live(usize),
}

thread_local! {
    static COMPARING: RefCell<HashSet<(ObjectIdentity, ObjectIdentity)>> = RefCell::new(HashSet::new());
    static FORMATTING: RefCell<HashSet<ObjectIdentity>> = RefCell::new(HashSet::new());
}

struct ComparisonGuard(ObjectIdentity, ObjectIdentity);

impl ComparisonGuard {
    fn enter(left: ObjectIdentity, right: ObjectIdentity) -> Option<Self> {
        COMPARING
            .with(|active| active.borrow_mut().insert((left, right)))
            .then(|| Self(left, right))
    }
}

impl Drop for ComparisonGuard {
    fn drop(&mut self) {
        COMPARING.with(|active| {
            let _ = active.borrow_mut().remove(&(self.0, self.1));
        });
    }
}

struct FormattingGuard(ObjectIdentity);

impl FormattingGuard {
    fn enter(identity: ObjectIdentity) -> Option<Self> {
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

impl FieldObject {
    pub(crate) fn from_source(source: Arc<dyn FieldObjectSource>) -> Self {
        Self(ObjectStorage::Live(source))
    }

    /// Read one current property without retaining a source lock.
    pub fn get(&self, name: &str) -> AuthResult<Option<FieldValue>> {
        match &self.0 {
            ObjectStorage::Owned(fields) => Ok(fields
                .lock()
                .map_err(|_| AuthError::internal("Field object lock poisoned"))?
                .get(name)
                .cloned()),
            ObjectStorage::Live(source) => source.get(name),
        }
    }

    /// Assign one own property and return its previous value. Cloned handles observe the assignment.
    /// Existing properties keep their position; a new property is appended.
    pub fn set(
        &self,
        name: impl Into<String>,
        value: FieldValue,
    ) -> AuthResult<Option<FieldValue>> {
        let name = name.into();
        match &self.0 {
            ObjectStorage::Owned(fields) => Ok(fields
                .lock()
                .map_err(|_| AuthError::internal("Field object lock poisoned"))?
                .insert(name, value)),
            ObjectStorage::Live(source) => source.set(name, value),
        }
    }

    /// Delete one own property without moving other properties. Return the removed value.
    /// `None` means absent; `Some(Undefined)` means the property existed with an undefined value.
    pub fn delete(&self, name: &str) -> AuthResult<Option<FieldValue>> {
        match &self.0 {
            ObjectStorage::Owned(fields) => Ok(fields
                .lock()
                .map_err(|_| AuthError::internal("Field object lock poisoned"))?
                .remove(name)),
            ObjectStorage::Live(source) => source.delete(name),
        }
    }

    /// Copy current own fields while retaining child identities.
    pub fn snapshot_fields(&self) -> AuthResult<FieldMap> {
        let mut fields = match &self.0 {
            ObjectStorage::Owned(fields) => fields
                .lock()
                .map_err(|_| AuthError::internal("Field object lock poisoned"))?
                .clone(),
            ObjectStorage::Live(source) => source.snapshot_fields()?,
        };
        fields.sort_property_order();
        Ok(fields)
    }

    /// Compare object identity without reading either object's properties.
    pub fn same_object(&self, other: &Self) -> bool {
        self.identity() == other.identity()
    }

    pub(crate) fn identity(&self) -> ObjectIdentity {
        match &self.0 {
            ObjectStorage::Owned(fields) => ObjectIdentity::Owned(Arc::as_ptr(fields) as usize),
            ObjectStorage::Live(source) => ObjectIdentity::Live(source.identity()),
        }
    }

    pub(crate) fn is_live(&self) -> bool {
        matches!(self.0, ObjectStorage::Live(_))
    }
}

impl From<FieldMap> for FieldObject {
    fn from(fields: FieldMap) -> Self {
        Self(ObjectStorage::Owned(Arc::new(Mutex::new(fields))))
    }
}

impl PartialEq for FieldObject {
    fn eq(&self, other: &Self) -> bool {
        match (&self.0, &other.0) {
            (ObjectStorage::Owned(_), ObjectStorage::Owned(_)) => {
                let Some(_guard) = ComparisonGuard::enter(self.identity(), other.identity()) else {
                    return true;
                };
                // Snapshot each side separately; recursive comparisons must not retain either lock.
                match (self.snapshot_fields(), other.snapshot_fields()) {
                    (Ok(left), Ok(right)) => left == right,
                    // Infallible equality cannot report a poisoned source. Explicit reads return the error.
                    _ => false,
                }
            }
            (ObjectStorage::Live(left), ObjectStorage::Live(right)) => {
                left.identity() == right.identity()
            }
            _ => false,
        }
    }
}

impl fmt::Debug for FieldObject {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.0 {
            ObjectStorage::Owned(_) => {
                let Some(_guard) = FormattingGuard::enter(self.identity()) else {
                    return f.write_str("[Circular]");
                };
                match self.snapshot_fields() {
                    Ok(fields) => fields.fmt(f),
                    Err(error) => f
                        .debug_struct("UnavailableObject")
                        .field("error", &error)
                        .finish(),
                }
            }
            ObjectStorage::Live(source) => f
                .debug_struct("LiveObject")
                .field("identity", &source.identity())
                .finish_non_exhaustive(),
        }
    }
}
