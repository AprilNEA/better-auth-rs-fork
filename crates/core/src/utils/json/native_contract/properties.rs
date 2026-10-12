use super::*;
use crate::field_value::{FieldObjectSource, FieldPropertyDescriptor};
use std::{any::Any, sync::Weak};

#[derive(Clone)]
enum Property {
    Data(FieldValue),
    Getter {
        callback: FieldFunction,
        enumerable: bool,
    },
}

pub(super) struct Properties {
    fields: Mutex<indexmap::IndexMap<String, Property>>,
    receiver: Mutex<Weak<FieldValue>>,
    observer: Observer,
}

impl Properties {
    pub(super) fn new(observer: &Observer) -> Arc<Self> {
        Arc::new(Self {
            fields: Mutex::default(),
            receiver: Mutex::default(),
            observer: observer.clone(),
        })
    }

    pub(super) fn bind(&self, value: FieldValue) -> Arc<FieldValue> {
        let value = Arc::new(value);
        *self.receiver.lock() = Arc::downgrade(&value);
        value
    }

    pub(super) fn receiver(&self) -> AuthResult<Arc<FieldValue>> {
        self.receiver
            .lock()
            .upgrade()
            .ok_or_else(|| AuthError::internal("Native getter receiver is absent"))
    }

    pub(super) fn getter(&self, name: &str, callback: FieldFunction, enumerable: bool) {
        let _ = self.fields.lock().insert(
            name.into(),
            Property::Getter {
                callback,
                enumerable,
            },
        );
    }
}

impl FieldObjectSource for Properties {
    fn own_keys(&self) -> AuthResult<Vec<String>> {
        Ok(self.fields.lock().keys().cloned().collect())
    }

    fn own_property_descriptor(&self, name: &str) -> AuthResult<Option<FieldPropertyDescriptor>> {
        Ok(self
            .fields
            .lock()
            .get(name)
            .map(|property| FieldPropertyDescriptor {
                enumerable: match property {
                    Property::Data(_) => true,
                    Property::Getter { enumerable, .. } => *enumerable,
                },
            }))
    }

    fn get(&self, _: &str) -> AuthResult<Option<FieldValue>> {
        Err(AuthError::internal(
            "Native getters require the original receiver",
        ))
    }

    fn get_with_receiver(
        &self,
        name: &str,
        receiver: &FieldValue,
    ) -> AuthResult<Option<FieldValue>> {
        let property = self.fields.lock().get(name).cloned();
        match property {
            None => Ok(None),
            Some(Property::Data(value)) => Ok(Some(value)),
            Some(Property::Getter { callback, .. }) => {
                let expected = self.receiver()?;
                self.observer.lock().record(
                    &format!("get:{name}"),
                    [(
                        "sameReceiver".into(),
                        receiver.strict_equals(&expected).into(),
                    )],
                );
                callback.call_with(receiver, &[]).map(Some)
            }
        }
    }

    fn set(&self, name: String, value: FieldValue) -> AuthResult<Option<FieldValue>> {
        Ok(
            match self.fields.lock().insert(name, Property::Data(value)) {
                Some(Property::Data(previous)) => Some(previous),
                _ => None,
            },
        )
    }

    fn delete(&self, name: &str) -> AuthResult<Option<FieldValue>> {
        Ok(match self.fields.lock().shift_remove(name) {
            Some(Property::Data(previous)) => Some(previous),
            _ => None,
        })
    }

    fn snapshot_fields(&self) -> AuthResult<FieldMap> {
        Err(AuthError::internal(
            "Native revival must read properties individually",
        ))
    }

    fn identity(&self) -> usize {
        std::ptr::from_ref(self) as usize
    }

    fn as_any(&self) -> Option<&dyn Any> {
        Some(self)
    }
}
