use super::*;
use better_auth_core::{
    FieldFunction, FieldObject,
    field_value::{FieldObjectSource, FieldPropertyDescriptor},
};
use std::sync::Weak;

type Getter = Arc<dyn Fn(&FieldValue) -> AuthResult<FieldValue> + Send + Sync>;

#[derive(Clone)]
enum Property {
    Value(FieldValue),
    Getter { read: Getter, enumerable: bool },
}

#[derive(Default)]
struct Properties(Mutex<indexmap::IndexMap<String, Property>>);

pub(super) struct Root {
    pub(super) value: FieldValue,
    owner: Arc<OnceLock<FieldValue>>,
    fields: Arc<Properties>,
}

impl Root {
    pub(super) fn new(kind: &str) -> Self {
        let fields = Arc::new(Properties::default());
        let object = FieldObject::from_source(fields.clone());
        let value = match kind {
            "date" => FieldDate::from_milliseconds_with_properties(NOW as f64, object).into(),
            "function" => {
                FieldFunction::contextual_with_properties(|_, _| Ok(FieldValue::Undefined), object)
                    .into()
            }
            _ => object.into(),
        };
        let owner = Arc::new(OnceLock::new());
        owner.set(value.clone()).unwrap();
        Self {
            value,
            owner,
            fields,
        }
    }

    pub(super) fn owner(&self) -> Weak<OnceLock<FieldValue>> {
        Arc::downgrade(&self.owner)
    }

    pub(super) fn data(&self, name: &str, value: FieldValue) {
        let _ = self
            .fields
            .0
            .lock()
            .unwrap()
            .insert(name.into(), Property::Value(value));
    }

    pub(super) fn getter(
        &self,
        name: &str,
        enumerable: bool,
        read: impl Fn(&FieldValue) -> AuthResult<FieldValue> + Send + Sync + 'static,
    ) {
        let _ = self.fields.0.lock().unwrap().insert(
            name.into(),
            Property::Getter {
                read: Arc::new(read),
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
        let property = self.0.lock().unwrap().get(name).cloned();
        match property {
            None => Ok(None),
            Some(Property::Value(value)) => Ok(Some(value)),
            Some(Property::Getter { read, .. }) => read(receiver).map(Some),
        }
    }

    fn set(&self, name: String, value: FieldValue) -> AuthResult<Option<FieldValue>> {
        Ok(
            match self.0.lock().unwrap().insert(name, Property::Value(value)) {
                Some(Property::Value(value)) => Some(value),
                _ => None,
            },
        )
    }

    fn delete(&self, _: &str) -> AuthResult<Option<FieldValue>> {
        Err(AuthError::internal(
            "Consumer contract does not delete native input properties",
        ))
    }

    fn snapshot_fields(&self) -> AuthResult<FieldMap> {
        Err(AuthError::internal(
            "Consumer inputs must retain getters until the actual property read",
        ))
    }

    fn identity(&self) -> usize {
        std::ptr::from_ref(self).addr()
    }
}
