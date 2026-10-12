use super::*;
use crate::field_value::{FieldObjectSource, FieldPropertyDescriptor};
use std::sync::{OnceLock, Weak};

type Getter = Arc<dyn Fn(&FieldValue) -> AuthResult<FieldValue> + Send + Sync>;

enum Property {
    Value(FieldValue),
    Getter { callback: Getter, enumerable: bool },
}

#[derive(Default)]
struct Properties(Mutex<indexmap::IndexMap<String, Property>>);

pub(super) struct Root {
    pub(super) value: FieldValue,
    expected: Arc<OnceLock<FieldValue>>,
    properties: Arc<Properties>,
}

impl Root {
    pub(super) fn new(kind: &str) -> AuthResult<Self> {
        Self::build(|fields| {
            Ok(match kind {
                "array" => {
                    let array = crate::FieldArray::with_length_and_properties(3, fields);
                    array.set(0, "array-value".into())?;
                    array.set(2, FieldValue::Undefined)?;
                    array.into()
                }
                "date" => crate::FieldDate::from_milliseconds_with_properties(
                    (NOW - 4_000) as f64,
                    fields,
                )
                .into(),
                "expiry" => crate::FieldDate::from_milliseconds_with_properties(
                    (NOW + 60_000) as f64,
                    fields,
                )
                .into(),
                "function" => crate::FieldFunction::contextual_with_properties(
                    |_, _| Ok(FieldValue::Undefined),
                    fields,
                )
                .into(),
                _ => fields.into(),
            })
        })
    }

    pub(super) fn build(
        create: impl FnOnce(crate::FieldObject) -> AuthResult<FieldValue>,
    ) -> AuthResult<Self> {
        let properties = Arc::new(Properties::default());
        let fields = crate::FieldObject::from_source(properties.clone());
        let value = create(fields)?;
        let expected = Arc::new(OnceLock::new());
        expected.set(value.clone()).unwrap();
        Ok(Self {
            value,
            expected,
            properties,
        })
    }

    pub(super) fn weak(&self) -> Weak<OnceLock<FieldValue>> {
        Arc::downgrade(&self.expected)
    }

    pub(super) fn data(&self, name: &str, value: FieldValue) {
        let _ = self
            .properties
            .0
            .lock()
            .unwrap()
            .insert(name.into(), Property::Value(value));
    }

    pub(super) fn getter(
        &self,
        name: &str,
        enumerable: bool,
        callback: impl Fn(&FieldValue) -> AuthResult<FieldValue> + Send + Sync + 'static,
    ) {
        let _ = self.properties.0.lock().unwrap().insert(
            name.into(),
            Property::Getter {
                callback: Arc::new(callback),
                enumerable,
            },
        );
    }
}

impl FieldObjectSource for Properties {
    fn own_keys(&self) -> AuthResult<Vec<String>> {
        Ok(self.0.lock().unwrap().keys().cloned().collect())
    }

    fn own_property_descriptor(&self, name: &str) -> AuthResult<Option<FieldPropertyDescriptor>> {
        Ok(self
            .0
            .lock()
            .unwrap()
            .get(name)
            .map(|property| FieldPropertyDescriptor {
                enumerable: match property {
                    Property::Value(_) => true,
                    Property::Getter { enumerable, .. } => *enumerable,
                },
            }))
    }

    fn get(&self, name: &str) -> AuthResult<Option<FieldValue>> {
        self.get_with_receiver(name, &FieldValue::Undefined)
    }

    fn get_with_receiver(
        &self,
        name: &str,
        receiver: &FieldValue,
    ) -> AuthResult<Option<FieldValue>> {
        let callback = match self.0.lock().unwrap().get(name) {
            Some(Property::Value(value)) => return Ok(Some(value.clone())),
            Some(Property::Getter { callback, .. }) => callback.clone(),
            None => return Ok(None),
        };
        callback(receiver).map(Some)
    }

    fn set(&self, name: String, value: FieldValue) -> AuthResult<Option<FieldValue>> {
        match self.0.lock().unwrap().insert(name, Property::Value(value)) {
            Some(Property::Value(value)) => Ok(Some(value)),
            _ => Ok(None),
        }
    }

    fn delete(&self, _: &str) -> AuthResult<Option<FieldValue>> {
        Err(AuthError::internal(
            "Verification contract does not delete root properties",
        ))
    }

    fn snapshot_fields(&self) -> AuthResult<FieldMap> {
        Err(AuthError::internal(
            "Verification native roots must remain live until spread",
        ))
    }

    fn identity(&self) -> usize {
        std::ptr::from_ref(self).addr()
    }
}
