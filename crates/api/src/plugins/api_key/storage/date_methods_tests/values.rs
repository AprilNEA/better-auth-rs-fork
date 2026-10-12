use super::*;
use better_auth_core::field_value::{FieldObjectSource, FieldPropertyDescriptor};

#[derive(Clone, Default)]
struct Receiver(Arc<OnceLock<Weak<FieldValue>>>);

impl Receiver {
    fn bind(&self, value: FieldValue) -> Arc<FieldValue> {
        let value = Arc::new(value);
        self.0.set(Arc::downgrade(&value)).unwrap();
        value
    }

    fn get(&self) -> Arc<FieldValue> {
        self.0.get().unwrap().upgrade().unwrap()
    }
}

struct Properties {
    fields: FieldMap,
    getters: Vec<&'static str>,
    fail_get: Option<&'static str>,
    original: FieldValue,
    observer: Observer,
    receiver: Receiver,
}

impl FieldObjectSource for Properties {
    fn own_keys(&self) -> AuthResult<Vec<String>> {
        Ok(self.fields.keys().cloned().collect())
    }

    fn own_property_descriptor(&self, name: &str) -> AuthResult<Option<FieldPropertyDescriptor>> {
        Ok(self
            .fields
            .contains_key(name)
            .then_some(FieldPropertyDescriptor {
                enumerable: !matches!(name, "toISOString" | "toJSON" | "valueOf"),
            }))
    }

    fn get(&self, name: &str) -> AuthResult<Option<FieldValue>> {
        self.get_with_receiver(name, &self.receiver.get())
    }

    fn get_with_receiver(
        &self,
        name: &str,
        receiver: &FieldValue,
    ) -> AuthResult<Option<FieldValue>> {
        if self.getters.contains(&name) {
            self.observer.lock().unwrap().record(
                &format!("get:{name}"),
                [(
                    "sameReceiver".into(),
                    receiver.strict_equals(&self.receiver.get()).into(),
                )],
            );
        }
        if self.fail_get == Some(name) {
            return Err(AuthError::from_thrown(self.original.clone()));
        }
        Ok(self.fields.get(name).cloned())
    }

    fn set(&self, _: String, _: FieldValue) -> AuthResult<Option<FieldValue>> {
        Err(AuthError::internal(
            "Date method contract does not assign properties",
        ))
    }

    fn delete(&self, _: &str) -> AuthResult<Option<FieldValue>> {
        Err(AuthError::internal(
            "Date method contract does not delete properties",
        ))
    }

    fn snapshot_fields(&self) -> AuthResult<FieldMap> {
        Err(AuthError::internal(
            "Native method accessors must not be flattened",
        ))
    }

    fn identity(&self) -> usize {
        std::ptr::from_ref(self) as usize
    }
}

pub(super) fn receiver(
    observer: &Observer,
    original: &FieldValue,
    mode: &str,
) -> (Arc<FieldValue>, Arc<FieldValue>) {
    let returned = Receiver::default();
    let mut returned_fields = FieldMap::from([
        ("marker".into(), "method-result".into()),
        ("optional".into(), FieldValue::Undefined),
    ]);
    if mode == "object-result" {
        let observed = observer.clone();
        let expected = returned.clone();
        let _ = returned_fields.insert(
            "toJSON".into(),
            FieldFunction::contextual(move |this, args| {
                observed
                    .lock()
                    .unwrap()
                    .call("call:result.toJSON", this, &expected.get(), args)?;
                Ok(FieldMap::from([
                    ("result".into(), args.first().cloned().unwrap_or_default()),
                    ("retained".into(), true.into()),
                ])
                .into())
            })
            .into(),
        );
    }
    let returned = returned.bind(
        FieldObject::from_source(Arc::new(Properties {
            fields: returned_fields,
            getters: Vec::new(),
            fail_get: None,
            original: original.clone(),
            observer: observer.clone(),
            receiver: returned.clone(),
        }))
        .into(),
    );
    let expected = Receiver::default();
    let mut fields = FieldMap::new();
    let mut getters = Vec::new();
    let fail_get = if mode == "date-to-json" {
        let _ = fields.insert("toJSON".into(), FieldValue::Undefined);
        getters.push("toJSON");
        Some("toJSON")
    } else {
        let observed = observer.clone();
        let receiver = expected.clone();
        let original = original.clone();
        let fails = mode == "call-throws";
        let result = match mode {
            "object-undefined" => FieldValue::Undefined,
            "object-result" => returned.as_ref().clone(),
            _ => "method-iso".into(),
        };
        let _ = fields.insert(
            "toISOString".into(),
            FieldFunction::contextual(move |this, args| {
                observed
                    .lock()
                    .unwrap()
                    .call("call:toISOString", this, &receiver.get(), args)?;
                if fails {
                    return Err(AuthError::from_thrown(original.clone()));
                }
                Ok(result.clone())
            })
            .into(),
        );
        getters.push("toISOString");
        (mode == "get-throws").then_some("toISOString")
    };
    if mode == "ttl-before-serialization" {
        let observed = observer.clone();
        let receiver = expected.clone();
        let original = original.clone();
        let _ = fields.insert(
            "valueOf".into(),
            FieldFunction::contextual(move |this, args| {
                observed
                    .lock()
                    .unwrap()
                    .call("call:valueOf", this, &receiver.get(), args)?;
                Err(AuthError::from_thrown(original.clone()))
            })
            .into(),
        );
        getters.push("valueOf");
    }
    let properties = FieldObject::from_source(Arc::new(Properties {
        fields,
        getters,
        fail_get,
        original: original.clone(),
        observer: observer.clone(),
        receiver: expected.clone(),
    }));
    let receiver = match mode {
        "date-to-json" => FieldDate::from_milliseconds_with_properties(0.0, properties).into(),
        "invalid-date-iso" => {
            FieldDate::from_milliseconds_with_properties(f64::NAN, properties).into()
        }
        _ => properties.into(),
    };
    (expected.bind(receiver), returned)
}
