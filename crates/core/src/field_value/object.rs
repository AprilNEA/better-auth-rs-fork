use super::{FieldMap, FieldValue};
use crate::{AuthError, AuthResult};
use std::{
    any::Any,
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

/// Metadata used by operations that select an object's own enumerable properties.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FieldPropertyDescriptor {
    pub enumerable: bool,
}

/// A live object source. Property access must retain native values and child identities.
pub trait FieldObjectSource: Send + Sync {
    fn own_keys(&self) -> AuthResult<Vec<String>>;
    /// Inspect one current own property without evaluating its value or enumerating other keys.
    fn own_property_descriptor(&self, name: &str) -> AuthResult<Option<FieldPropertyDescriptor>>;
    fn has_property(&self, name: &str) -> AuthResult<bool> {
        Ok(self.own_keys()?.iter().any(|key| key == name))
    }
    fn get(&self, name: &str) -> AuthResult<Option<FieldValue>>;
    /// Read a property with the native receiver that owns this source.
    fn get_with_receiver(
        &self,
        name: &str,
        _receiver: &FieldValue,
    ) -> AuthResult<Option<FieldValue>> {
        self.get(name)
    }
    fn set(&self, name: String, value: FieldValue) -> AuthResult<Option<FieldValue>>;
    /// Assign a property without reading its previous value or replacing setter errors.
    fn set_with_receiver(
        &self,
        name: String,
        value: FieldValue,
        _receiver: &FieldValue,
    ) -> AuthResult<()> {
        self.set(name, value).map(drop)
    }
    fn delete(&self, name: &str) -> AuthResult<Option<FieldValue>>;
    fn snapshot_fields(&self) -> AuthResult<FieldMap>;
    fn identity(&self) -> usize;

    #[doc(hidden)]
    fn clone_seed(&self) -> AuthResult<Option<super::ObjectCloneSeed>> {
        Ok(None)
    }

    fn as_any(&self) -> Option<&dyn Any> {
        None
    }
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
    /// Retain a live source without reading its properties.
    pub fn from_source(source: Arc<dyn FieldObjectSource>) -> Self {
        Self(ObjectStorage::Live(source))
    }

    /// Capture property names without evaluating property values.
    pub fn own_keys(&self) -> AuthResult<Vec<String>> {
        let mut keys = match &self.0 {
            ObjectStorage::Owned(fields) => fields
                .lock()
                .map_err(|_| AuthError::internal("Field object lock poisoned"))?
                .keys()
                .cloned()
                .collect(),
            ObjectStorage::Live(source) => source.own_keys()?,
        };
        keys.sort_by_key(|name| {
            crate::utils::json::array_index(name).map_or((true, 0), |index| (false, index))
        });
        Ok(keys)
    }

    /// Inspect a current own property. Absence differs from a non-enumerable property.
    pub fn own_property_descriptor(
        &self,
        name: &str,
    ) -> AuthResult<Option<FieldPropertyDescriptor>> {
        match &self.0 {
            ObjectStorage::Owned(fields) => Ok(fields
                .lock()
                .map_err(|_| AuthError::internal("Field object lock poisoned"))?
                .contains_key(name)
                .then_some(FieldPropertyDescriptor { enumerable: true })),
            ObjectStorage::Live(source) => source.own_property_descriptor(name),
        }
    }

    /// Capture enumerable keys before reading values, as required by JSON and `Object.keys`.
    pub fn enumerable_keys(&self) -> AuthResult<Vec<String>> {
        let mut keys = Vec::new();
        for name in self.own_keys()? {
            if self
                .own_property_descriptor(&name)?
                .is_some_and(|descriptor| descriptor.enumerable)
            {
                keys.push(name);
            }
        }
        Ok(keys)
    }

    pub(crate) fn source<T: 'static>(&self) -> Option<&T> {
        match &self.0 {
            ObjectStorage::Live(source) => source.as_any()?.downcast_ref(),
            ObjectStorage::Owned(_) => None,
        }
    }

    pub(crate) fn clone_seed(&self) -> AuthResult<super::ObjectCloneSeed> {
        if let ObjectStorage::Live(source) = &self.0
            && let Some(seed) = source.clone_seed()?
        {
            return Ok(seed);
        }
        let fields = Arc::new(Mutex::new(FieldMap::new()));
        let object = Self(ObjectStorage::Owned(fields.clone()));
        Ok(super::ObjectCloneSeed {
            object,
            state: Vec::new(),
            original_record: None,
            prepare: Box::new(move |values, _| {
                Ok(super::structured_clone::prepare_clone(fields, values))
            }),
        })
    }

    /// Read one current property without retaining a source lock.
    pub fn get(&self, name: &str) -> AuthResult<Option<FieldValue>> {
        self.get_with_receiver(name, &FieldValue::Object(self.clone()))
    }

    pub(crate) fn get_with_receiver(
        &self,
        name: &str,
        receiver: &FieldValue,
    ) -> AuthResult<Option<FieldValue>> {
        match &self.0 {
            ObjectStorage::Owned(fields) => Ok(fields
                .lock()
                .map_err(|_| AuthError::internal("Field object lock poisoned"))?
                .get(name)
                .cloned()),
            ObjectStorage::Live(source) => source.get_with_receiver(name, receiver),
        }
    }

    /// Check property presence without evaluating the property value.
    /// Sources with prototype properties must provide their own presence check.
    pub fn has_property(&self, name: &str) -> AuthResult<bool> {
        match &self.0 {
            ObjectStorage::Owned(fields) => Ok(fields
                .lock()
                .map_err(|_| AuthError::internal("Field object lock poisoned"))?
                .contains_key(name)),
            ObjectStorage::Live(source) => source.has_property(name),
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

    pub(crate) fn assign(
        &self,
        name: &str,
        value: FieldValue,
        receiver: &FieldValue,
    ) -> AuthResult<()> {
        match &self.0 {
            ObjectStorage::Owned(_) => self.set(name, value).map(drop),
            ObjectStorage::Live(source) => source.set_with_receiver(name.into(), value, receiver),
        }
    }

    pub(crate) fn prepare_fields(
        &self,
        fields: FieldMap,
    ) -> AuthResult<super::structured_clone::CloneWrite> {
        match &self.0 {
            ObjectStorage::Owned(target) => Ok(super::structured_clone::prepare_clone(
                target.clone(),
                fields,
            )),
            ObjectStorage::Live(_) => Err(AuthError::internal(
                "Structured clone requires an owned property target",
            )),
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

impl From<FieldObject> for FieldValue {
    fn from(value: FieldObject) -> Self {
        Self::Object(value)
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
