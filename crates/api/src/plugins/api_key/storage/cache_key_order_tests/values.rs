use super::*;
use better_auth_core::field_value::{FieldObjectSource, FieldPropertyDescriptor};

struct Properties {
    fields: FieldMap,
    hidden: &'static str,
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
                enumerable: name != self.hidden,
            }))
    }

    fn get(&self, name: &str) -> AuthResult<Option<FieldValue>> {
        Ok(self.fields.get(name).cloned())
    }

    fn set(&self, _: String, _: FieldValue) -> AuthResult<Option<FieldValue>> {
        Err(AuthError::internal("Error evidence must not be mutated"))
    }

    fn delete(&self, _: &str) -> AuthResult<Option<FieldValue>> {
        Err(AuthError::internal("Error evidence must not be deleted"))
    }

    fn snapshot_fields(&self) -> AuthResult<FieldMap> {
        Err(AuthError::internal(
            "Native evidence must retain its property descriptors",
        ))
    }

    fn identity(&self) -> usize {
        std::ptr::from_ref(self) as usize
    }
}

pub(super) fn errors(name: &str) -> FieldMap {
    ["key", "storage", "peer", "repeatedReference"]
        .into_iter()
        .map(|kind| {
            let fields = FieldMap::from([
                ("kind".into(), kind.into()),
                ("ownUndefined".into(), FieldValue::Undefined),
                (
                    "detail".into(),
                    FieldMap::from([("scenario".into(), name.into())]).into(),
                ),
                (
                    "token".into(),
                    FieldMap::from([("owner".into(), kind.into())]).into(),
                ),
            ]);
            (
                kind.into(),
                FieldObject::from_source(Arc::new(Properties {
                    fields,
                    hidden: "token",
                }))
                .into(),
            )
        })
        .collect()
}

struct Key {
    slot: &'static str,
    state: Weak<Mutex<State>>,
    receiver: Arc<OnceLock<Weak<FieldValue>>>,
}

impl Key {
    fn receiver(&self) -> Arc<FieldValue> {
        self.receiver.get().unwrap().upgrade().unwrap()
    }
}

impl FieldObjectSource for Key {
    fn own_keys(&self) -> AuthResult<Vec<String>> {
        Ok(vec!["slot".into(), "toString".into()])
    }

    fn own_property_descriptor(&self, name: &str) -> AuthResult<Option<FieldPropertyDescriptor>> {
        Ok(match name {
            "slot" => Some(FieldPropertyDescriptor { enumerable: true }),
            "toString" => Some(FieldPropertyDescriptor { enumerable: false }),
            _ => None,
        })
    }

    fn get(&self, name: &str) -> AuthResult<Option<FieldValue>> {
        self.get_with_receiver(name, &self.receiver())
    }

    fn get_with_receiver(
        &self,
        name: &str,
        receiver: &FieldValue,
    ) -> AuthResult<Option<FieldValue>> {
        if name == "slot" {
            return Ok(Some(self.slot.into()));
        }
        if name != "toString" {
            return Ok(None);
        }
        let shared = self.state.upgrade().unwrap();
        let mut state = shared.lock().unwrap();
        let slot = self.slot;
        let count = state.counts[slot]["getter"].as_u64().unwrap() + 1;
        state.counts[slot]["getter"] = count.into();
        state.trace.push(format!("primitive:get:{slot}"));
        state.observer.call(
            &format!("get:{slot}.toString"),
            receiver,
            &self.receiver(),
            &[],
        )?;
        let fails = matches!(
            state.scenario["kind"].as_str().unwrap(),
            "key-error" | "orphan"
        ) && state.scenario["slot"] == slot;
        if fails && state.scenario["phase"] == "primitive-get" {
            return Err(AuthError::from_thrown(state.error("key")));
        }
        let observed = self.state.clone();
        let expected = self.receiver.clone();
        Ok(Some(
            FieldFunction::contextual(move |receiver, arguments| {
                let shared = observed.upgrade().unwrap();
                let mut state = shared.lock().unwrap();
                let count = state.counts[slot]["method"].as_u64().unwrap() + 1;
                state.counts[slot]["method"] = count.into();
                state.trace.push(format!("primitive:call:{slot}"));
                let expected = expected.get().unwrap().upgrade().unwrap();
                state.observer.call(
                    &format!("call:{slot}.toString"),
                    receiver,
                    &expected,
                    arguments,
                )?;
                assert!(receiver.strict_equals(&expected));
                assert!(arguments.is_empty());
                if slot == "reference" && count > 1 {
                    return Err(AuthError::from_thrown(state.error("repeatedReference")));
                }
                if fails && state.scenario["phase"] == "primitive-call" {
                    return Err(AuthError::from_thrown(state.error("key")));
                }
                Ok(match slot {
                    "reference" => "owner",
                    "hash" => "hash",
                    "id" => "key",
                    _ => return Err(AuthError::internal("Unknown cache-key conversion slot")),
                }
                .into())
            })
            .into(),
        ))
    }

    fn set(&self, _: String, _: FieldValue) -> AuthResult<Option<FieldValue>> {
        Err(AuthError::internal(
            "Cache key evidence must not be mutated",
        ))
    }

    fn delete(&self, _: &str) -> AuthResult<Option<FieldValue>> {
        Err(AuthError::internal(
            "Cache key evidence must not be deleted",
        ))
    }

    fn snapshot_fields(&self) -> AuthResult<FieldMap> {
        Err(AuthError::internal(
            "Cache key accessors must retain their receiver identity",
        ))
    }

    fn identity(&self) -> usize {
        std::ptr::from_ref(self) as usize
    }
}

pub(super) fn key(state: &Shared) -> AuthResult<(ApiKey, Vec<Arc<FieldValue>>)> {
    let mut roots = Vec::new();
    let mut fields = FieldMap::new();
    for (field, slot) in [("id", "id"), ("key", "hash"), ("referenceId", "reference")] {
        let receiver = Arc::new(OnceLock::new());
        let value = Arc::new(FieldValue::from(FieldObject::from_source(Arc::new(Key {
            slot,
            state: Arc::downgrade(state),
            receiver: receiver.clone(),
        }))));
        receiver.set(Arc::downgrade(&value)).unwrap();
        let _ = fields.insert(field.into(), value.as_ref().clone());
        roots.push(value);
    }
    fields.extend([
        ("configId".into(), "default".into()),
        (
            "createdAt".into(),
            FieldDate::from_milliseconds(2_000_000_000_000.0).into(),
        ),
        (
            "updatedAt".into(),
            FieldDate::from_milliseconds(2_000_000_000_000.0).into(),
        ),
    ]);
    let key = ApiKey::from_field_values(fields)?;
    let mut state = state.lock().unwrap();
    let reference = if state.scenario["operation"] == "put" {
        vec!["kept".into()]
    } else {
        vec![key.id.field_value(), "kept".into()]
    };
    state.entries = vec![
        ("api-key:hash".into(), "stored-hash".into()),
        ("api-key:by-id:key".into(), "stored-id".into()),
        ("api-key:by-ref:owner".into(), reference.into()),
        (
            "unrelated".into(),
            FieldMap::from([
                ("retained".into(), true.into()),
                ("ownUndefined".into(), FieldValue::Undefined),
            ])
            .into(),
        ),
    ];
    Ok((key, roots))
}
