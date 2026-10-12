use super::super::object::Root;
use super::*;
use std::sync::OnceLock;

const ISO: &str = "2030-01-02T03:04:05.000Z";

struct State {
    kind: String,
    original: FieldValue,
    observer: Observer,
    input: OnceLock<FieldValue>,
    map_result: OnceLock<FieldValue>,
    serialized_receiver: Mutex<Option<FieldValue>>,
}

fn root(kind: &str) -> AuthResult<Root> {
    Root::build(|fields| {
        Ok(match kind {
            "array" => {
                let array = crate::FieldArray::with_length_and_properties(1, fields);
                array.set(0, ISO.into())?;
                array.into()
            }
            "date" => {
                crate::FieldDate::from_milliseconds_with_properties((NOW - 2_000) as f64, fields)
                    .into()
            }
            "expiry" => {
                crate::FieldDate::from_milliseconds_with_properties((NOW + 60_000) as f64, fields)
                    .into()
            }
            "function" => crate::FieldFunction::contextual_with_properties(
                |_, _| Ok(FieldValue::Undefined),
                fields,
            )
            .into(),
            _ => fields.into(),
        })
    })
}

fn method(
    root: &Root,
    name: &str,
    state: &Arc<State>,
    callback: impl Fn(&State, &FieldValue, &[FieldValue]) -> AuthResult<FieldValue>
    + Send
    + Sync
    + 'static,
) {
    let expected = root.weak();
    let weak_state = Arc::downgrade(state);
    let phase = format!("call:{name}");
    let function: FieldValue = crate::FieldFunction::contextual(move |receiver, arguments| {
        let state = weak_state.upgrade().unwrap();
        let expected = expected.upgrade().unwrap();
        state.observer.lock().unwrap().call(
            &phase,
            receiver,
            expected.get().unwrap(),
            arguments,
        )?;
        callback(&state, receiver, arguments)
    })
    .into();
    let expected = root.weak();
    let state = Arc::downgrade(state);
    let phase = format!("get:{name}");
    root.getter(name, false, move |receiver| {
        let state = state.upgrade().unwrap();
        let expected = expected.upgrade().unwrap();
        state
            .observer
            .lock()
            .unwrap()
            .call(&phase, receiver, expected.get().unwrap(), &[])?;
        Ok(function.clone())
    });
}

pub(super) struct Input {
    pub(super) value: FieldValue,
    pub(super) original: FieldValue,
    nested: FieldValue,
    state: Arc<State>,
    _roots: Vec<Root>,
}

impl Input {
    pub(super) fn new(name: &str, kind: &str, observer: Observer) -> AuthResult<Self> {
        let original: FieldValue = FieldMap::from([
            ("failure".into(), name.into()),
            ("ownUndefined".into(), FieldValue::Undefined),
        ])
        .into();
        let nested: FieldValue = FieldMap::from([
            ("iso".into(), ISO.into()),
            ("date".into(), date(-1_000)),
            (
                "callback".into(),
                crate::FieldFunction::contextual(|_, _| Ok(FieldValue::Undefined)).into(),
            ),
        ])
        .into();
        let record = || {
            FieldMap::from([
                ("id".into(), "native-row".into()),
                ("identifier".into(), "subject".into()),
                ("value".into(), ISO.into()),
                ("expiresAt".into(), date(60_000)),
                ("nested".into(), nested.clone()),
            ])
        };
        let state = Arc::new(State {
            kind: kind.into(),
            original: original.clone(),
            observer,
            input: OnceLock::new(),
            map_result: OnceLock::new(),
            serialized_receiver: Mutex::default(),
        });
        let mut roots = Vec::new();
        let value = match kind {
            "empty" => "".into(),
            "null" => FieldValue::Null,
            "undefined" => FieldValue::Undefined,
            "false" => false.into(),
            "true" => true.into(),
            "number" => 42.into(),
            "date" | "function" => {
                let input = root(kind)?;
                for (name, value) in record() {
                    input.data(&name, value);
                }
                let value = input.value.clone();
                roots.push(input);
                value
            }
            "array" => vec![ISO.into(), nested.clone()].into(),
            "object" => record().into(),
            "string-object" => FieldValue::from(record()).stringify_native()?,
            "string-true" => "true".into(),
            "string-empty" => r#""""#.into(),
            kind if kind.starts_with("map-") => {
                let input = root("array")?;
                let result = if kind == "map-number" {
                    42.into()
                } else {
                    let result = root(match kind {
                        "map-date" => "date",
                        "map-function" => "function",
                        _ => "object",
                    })?;
                    for (name, value) in record() {
                        result.data(&name, value);
                    }
                    if !matches!(kind, "map-date" | "map-function") {
                        result.data("expiresAt", ISO.into());
                    }
                    if kind == "map-expiry" {
                        let expected = result.weak();
                        let state = Arc::downgrade(&state);
                        result.getter("expiresAt", false, move |receiver| {
                            let state = state.upgrade().unwrap();
                            let expected = expected.upgrade().unwrap();
                            state.observer.lock().unwrap().call(
                                "get:expiresAt",
                                receiver,
                                expected.get().unwrap(),
                                &[],
                            )?;
                            Ok(date(60_000))
                        });
                    }
                    if kind == "map-date-method" {
                        let expiry = root("expiry")?;
                        method(&expiry, "getTime", &state, |_, _, arguments| {
                            assert!(arguments.is_empty());
                            Ok((NOW + 45_999).into())
                        });
                        result.data("expiresAt", expiry.value.clone());
                        roots.push(expiry);
                    }
                    let value = result.value.clone();
                    roots.push(result);
                    value
                };
                state.map_result.set(result).unwrap();
                method(&input, "map", &state, |state, _, arguments| {
                    assert_eq!(arguments.len(), 1);
                    let FieldValue::Function(callback) = &arguments[0] else {
                        return Err(AuthError::internal(
                            "Revival must supply its native callback",
                        ));
                    };
                    let revived = callback.call_with(
                        &"ignored receiver".into(),
                        &[ISO.into(), 0.into(), state.input.get().unwrap().clone()],
                    )?;
                    let mut observer = state.observer.lock().unwrap();
                    let value = observer.observe(&revived)?;
                    observer.record("map:callback", [("value".into(), value)]);
                    if state.kind == "map-error" {
                        return Err(AuthError::from_thrown(state.original.clone()));
                    }
                    Ok(state.map_result.get().unwrap().clone())
                });
                let value = input.value.clone();
                roots.push(input);
                value
            }
            "toJSON-mutate" | "toJSON-undefined" | "toJSON-error" | "set-error" => {
                let input: FieldValue = record().into();
                let weak_state = Arc::downgrade(&state);
                let callback = crate::FieldFunction::contextual(move |receiver, arguments| {
                    let state = weak_state.upgrade().unwrap();
                    let input = state.input.get().unwrap();
                    state.observer.lock().unwrap().call(
                        "call:toJSON",
                        receiver,
                        input,
                        arguments,
                    )?;
                    assert_eq!(arguments, &[FieldValue::from("")]);
                    assert!(!receiver.strict_equals(input));
                    *state.serialized_receiver.lock().unwrap() = Some(receiver.clone());
                    receiver
                        .set_model_property("mutation", "retained-after-serialization".into())?;
                    receiver.set_model_property("value", "mutated-by-toJSON".into())?;
                    if state.kind == "toJSON-error" {
                        return Err(AuthError::from_thrown(state.original.clone()));
                    }
                    if state.kind == "toJSON-undefined" {
                        return Ok(FieldValue::Undefined);
                    }
                    Ok(FieldMap::from([
                        ("stored".into(), "custom".into()),
                        ("value".into(), receiver.model_property("value")?),
                    ])
                    .into())
                });
                input.set_model_property("toJSON", callback.into())?;
                input
            }
            _ => {
                return Err(AuthError::internal(
                    "Unknown Verification read/update contract",
                ));
            }
        };
        state.input.set(value.clone()).unwrap();
        Ok(Self {
            value,
            original,
            nested,
            state,
            _roots: roots,
        })
    }

    pub(super) fn patch(&self) -> VerificationUpdate {
        VerificationUpdate {
            value: "updated-value".into(),
            expires_at: crate::SchemaValue::from_field(if self.state.kind == "map-expiry" {
                FieldValue::Null
            } else {
                FieldValue::Undefined
            }),
            ..Default::default()
        }
    }

    pub(super) fn identities(&self, result: &FieldValue) -> AuthResult<Json> {
        let nested = if result.is_null() || result.is_undefined() {
            FieldValue::Undefined
        } else {
            result.model_property("nested")?
        };
        Ok(json!({
            "sameInput": result.strict_equals(&self.value),
            "sameMapResult": self.state.map_result.get().is_some_and(|value| result.strict_equals(value)),
            "sameSerializedReceiver": self.state.serialized_receiver.lock().unwrap().as_ref().is_some_and(|value| result.strict_equals(value)),
            "sameNested": nested.strict_equals(&self.nested),
        }))
    }
}
