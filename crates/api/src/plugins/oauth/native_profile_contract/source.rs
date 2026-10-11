use super::*;
use better_auth_core::{
    FieldObject,
    field_value::{FieldObjectSource, FieldPropertyDescriptor},
};
use std::collections::{HashMap, HashSet};

#[derive(Clone, Default)]
pub(super) struct Log(Arc<Mutex<(String, Vec<Value>)>>);

impl Log {
    pub fn phase(&self, phase: &str) -> String {
        std::mem::replace(&mut self.0.lock().unwrap().0, phase.into())
    }

    pub fn event(&self, event: Value) {
        let mut log = self.0.lock().unwrap();
        let mut fields = serde_json::Map::new();
        fields.insert("phase".into(), log.0.clone().into());
        fields.extend(event.as_object().unwrap().clone());
        log.1.push(Value::Object(fields));
    }

    pub fn take(&self) -> Vec<Value> {
        std::mem::take(&mut self.0.lock().unwrap().1)
    }
}

#[derive(Clone, Copy)]
pub(super) enum Getter {
    Throw,
    Tail,
    ThrowingTail,
}

pub(super) struct Source {
    fields: Mutex<FieldMap>,
    hidden: HashSet<String>,
    getters: HashMap<String, Getter>,
    label: Option<&'static str>,
    log: Log,
    failure: FieldValue,
}

impl Source {
    pub fn value(
        fields: FieldMap,
        label: Option<&'static str>,
        log: Log,
        failure: FieldValue,
        hidden: &[&str],
        getters: &[(&str, Getter)],
    ) -> FieldValue {
        FieldValue::Object(FieldObject::from_source(Arc::new(Self {
            fields: Mutex::new(fields),
            hidden: hidden.iter().map(|name| (*name).into()).collect(),
            getters: getters
                .iter()
                .map(|(name, value)| ((*name).into(), *value))
                .collect(),
            label,
            log,
            failure,
        })))
    }

    fn event(&self, kind: &str, key: &str) {
        if let Some(label) = self.label {
            self.log
                .event(json!({"kind": kind, "object": label, "key": key}));
        }
    }
}

impl FieldObjectSource for Source {
    fn own_keys(&self) -> AuthResult<Vec<String>> {
        let keys: Vec<_> = self.fields.lock().unwrap().keys().cloned().collect();
        if let Some(label) = self.label {
            self.log
                .event(json!({"kind": "own-keys", "object": label, "keys": keys}));
        }
        Ok(keys)
    }

    fn own_property_descriptor(&self, name: &str) -> AuthResult<Option<FieldPropertyDescriptor>> {
        self.event("descriptor", name);
        Ok(self
            .fields
            .lock()
            .unwrap()
            .contains_key(name)
            .then(|| FieldPropertyDescriptor {
                enumerable: !self.hidden.contains(name),
            }))
    }

    fn has_property(&self, name: &str) -> AuthResult<bool> {
        Ok(self.fields.lock().unwrap().contains_key(name))
    }

    fn get(&self, name: &str) -> AuthResult<Option<FieldValue>> {
        let value = self.fields.lock().unwrap().get(name).cloned();
        if value.is_none() {
            return Ok(None);
        }
        self.event("get", name);
        match self.getters.get(name) {
            Some(Getter::Throw) => {
                self.event("getter-throw", name);
                Err(AuthError::from_thrown(self.failure.clone()))
            }
            Some(Getter::Tail | Getter::ThrowingTail) => {
                self.event("getter", name);
                if matches!(self.getters.get(name), Some(Getter::ThrowingTail)) {
                    Err(AuthError::from_thrown(self.failure.clone()))
                } else {
                    Ok(Some(object([("kept", true.into())])))
                }
            }
            None => Ok(value),
        }
    }

    fn set(&self, name: String, value: FieldValue) -> AuthResult<Option<FieldValue>> {
        // Proxy [[Set]] checks the receiver descriptor before defining an own property.
        let _ = self.own_property_descriptor(&name)?;
        Ok(self.fields.lock().unwrap().insert(name, value))
    }

    fn delete(&self, name: &str) -> AuthResult<Option<FieldValue>> {
        Ok(self.fields.lock().unwrap().remove(name))
    }

    fn snapshot_fields(&self) -> AuthResult<FieldMap> {
        let mut fields = FieldMap::new();
        for name in self.own_keys()? {
            if self
                .own_property_descriptor(&name)?
                .is_some_and(|descriptor| descriptor.enumerable)
            {
                if let Some(value) = self.get(&name)? {
                    fields.insert(name, value);
                }
            }
        }
        Ok(fields)
    }

    fn identity(&self) -> usize {
        std::ptr::from_ref(self).addr()
    }
}
