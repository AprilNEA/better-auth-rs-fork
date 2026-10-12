use super::*;
use object::Root;
use std::sync::OnceLock;

const ISO: &str = "2030-01-02T03:04:05.000Z";

#[derive(Default)]
struct Counters {
    expiry_reads: usize,
    conversion_calls: usize,
}

struct State {
    name: String,
    original: FieldValue,
    input: OnceLock<FieldValue>,
    counters: Mutex<Counters>,
    entries: Entries,
    observer: Observer,
}

impl State {
    fn effect(&self, phase: &str, fields: impl IntoIterator<Item = (String, Json)>) {
        assert!(!self.entries.lock().unwrap().contains_key(TARGET));
        let fields = fields
            .into_iter()
            .chain([("targetPresent".into(), false.into())]);
        self.observer.lock().unwrap().record(phase, fields);
    }

    fn fail(&self, phase: &str) -> AuthResult<FieldValue> {
        self.input
            .get()
            .unwrap()
            .set_model_property("mutation", format!("retained:{phase}").into())?;
        let error = self.observer.lock().unwrap().observe(&self.original)?;
        self.effect(
            "throw",
            [("stage".into(), phase.into()), ("error".into(), error)],
        );
        Err(AuthError::from_thrown(self.original.clone()))
    }
}

fn getter(
    root: &Root,
    name: &str,
    enumerable: bool,
    state: &Arc<State>,
    callback: impl Fn(&State) -> AuthResult<FieldValue> + Send + Sync + 'static,
) {
    let expected = root.weak();
    let state = Arc::downgrade(state);
    let phase = format!("get:{name}");
    root.getter(name, enumerable, move |receiver| {
        let state = state.upgrade().unwrap();
        let expected = expected.upgrade().unwrap();
        state.effect(
            &phase,
            [(
                "sameReceiver".into(),
                receiver.strict_equals(expected.get().unwrap()).into(),
            )],
        );
        callback(&state)
    });
}

pub(super) struct Input {
    pub(super) value: FieldValue,
    pub(super) original: FieldValue,
    nested: FieldValue,
    child_date: FieldValue,
    child_function: FieldValue,
    expiry_date: FieldValue,
    state: Arc<State>,
    _roots: Vec<Root>,
}

impl Input {
    pub(super) fn new(name: &str, entries: Entries, observer: Observer) -> AuthResult<Self> {
        let original: FieldValue = FieldMap::from([
            ("failure".into(), name.into()),
            ("ownUndefined".into(), FieldValue::Undefined),
        ])
        .into();
        let child_date = date(-3_000);
        let child_function: FieldValue =
            crate::FieldFunction::contextual(|_, _| Ok(FieldValue::Undefined)).into();
        let nested: FieldValue = FieldMap::from([
            ("iso".into(), ISO.into()),
            ("childDate".into(), child_date.clone()),
            ("childFunction".into(), child_function.clone()),
            ("ownUndefined".into(), FieldValue::Undefined),
        ])
        .into();
        let expiry = Root::new("expiry")?;
        let expiry_date = expiry.value.clone();
        let state = Arc::new(State {
            name: name.into(),
            original: original.clone(),
            input: OnceLock::new(),
            counters: Mutex::default(),
            entries,
            observer,
        });
        let record = || {
            FieldMap::from([
                ("id".into(), "native-row".into()),
                ("identifier".into(), "subject".into()),
                ("value".into(), ISO.into()),
                ("expiresAt".into(), expiry_date.clone()),
                ("createdAt".into(), ISO.into()),
                ("updatedAt".into(), ISO.into()),
                ("nested".into(), nested.clone()),
                ("ownUndefined".into(), FieldValue::Undefined),
                ("childFunction".into(), child_function.clone()),
            ])
        };
        let mut roots = Vec::new();
        let value = match name {
            "native-object-identity" | "native-expiry-date-skips-own-methods" => {
                if name == "native-expiry-date-skips-own-methods" {
                    for key in ["getTime", "valueOf", "toString"] {
                        getter(&expiry, key, false, &state, |_| {
                            Err(AuthError::internal(
                                "Date construction must skip own conversion methods",
                            ))
                        });
                    }
                }
                record().into()
            }
            name if name == "native-object-expiry-before-spread"
                || name.ends_with("-error")
                || name == "native-invalid-expiry-skips-spread" =>
            {
                let input = Root::new("object")?;
                input.data("id", "native-row".into());
                input.data("identifier", "subject".into());
                let converted = Root::new("object")?;
                let converted_receiver = converted.weak();
                let method_state = Arc::downgrade(&state);
                getter(&converted, "valueOf", false, &state, move |state| {
                    if state.name == "native-date-conversion-getter-error" {
                        return state.fail("valueOf-getter");
                    }
                    let expected = converted_receiver.clone();
                    let state = method_state.clone();
                    Ok(
                        crate::FieldFunction::contextual(move |receiver, arguments| {
                            let state = state.upgrade().unwrap();
                            let expected = expected.upgrade().unwrap();
                            let calls = {
                                let mut counters = state.counters.lock().unwrap();
                                counters.conversion_calls += 1;
                                counters.conversion_calls
                            };
                            let observed = state
                                .observer
                                .lock()
                                .unwrap()
                                .observe(&arguments.to_vec().into())?;
                            state.effect(
                                "call:valueOf",
                                [
                                    (
                                        "sameReceiver".into(),
                                        receiver.strict_equals(expected.get().unwrap()).into(),
                                    ),
                                    ("arguments".into(), observed),
                                    ("conversionCalls".into(), calls.into()),
                                ],
                            );
                            assert!(arguments.is_empty());
                            if state.name == "native-date-conversion-method-error" {
                                return state.fail("valueOf-method");
                            }
                            Ok((NOW + 60_000).into())
                        })
                        .into(),
                    )
                });
                let payload = nested.clone();
                getter(&input, "payload", true, &state, move |state| {
                    if state.name == "native-spread-getter-error" {
                        return state.fail("payload-getter");
                    }
                    let counters = state.counters.lock().unwrap();
                    state.effect(
                        "payload:read",
                        [
                            ("expiryReads".into(), counters.expiry_reads.into()),
                            ("conversionCalls".into(), counters.conversion_calls.into()),
                        ],
                    );
                    assert_eq!(counters.expiry_reads, 1);
                    assert_eq!(counters.conversion_calls, 1);
                    Ok(payload.clone())
                });
                let converted_value = converted.value.clone();
                getter(&input, "expiresAt", true, &state, move |state| {
                    let reads = {
                        let mut counters = state.counters.lock().unwrap();
                        counters.expiry_reads += 1;
                        counters.expiry_reads
                    };
                    state.effect("expiry:read", [("expiryReads".into(), reads.into())]);
                    if state.name == "native-expiry-getter-error" {
                        return state.fail("expiry-getter");
                    }
                    if state.name == "native-second-expiry-getter-error" && reads == 2 {
                        return state.fail("second-expiry-getter");
                    }
                    if state.name == "native-invalid-expiry-skips-spread" {
                        return Ok(FieldValue::Undefined);
                    }
                    Ok(if reads == 1 {
                        converted_value.clone()
                    } else {
                        "ignored-spread-expiry".into()
                    })
                });
                input.data("value", ISO.into());
                let value = input.value.clone();
                roots.extend([input, converted]);
                value
            }
            "native-expired-object" | "native-null-expiry" => {
                let input = Root::new("object")?;
                for (name, value) in record() {
                    input.data(&name, value);
                }
                input.data(
                    "expiresAt",
                    if name == "native-null-expiry" {
                        FieldValue::Null
                    } else {
                        date(-1)
                    },
                );
                getter(&input, "spreadWitness", true, &state, |state| {
                    state.effect("spread:witness", []);
                    Ok("read-before-expiration-gate".into())
                });
                let value = input.value.clone();
                roots.push(input);
                value
            }
            "native-array-root" | "native-date-root" => {
                let input = Root::new(if name == "native-array-root" {
                    "array"
                } else {
                    "date"
                })?;
                for (name, value) in FieldMap::from([
                    ("id".into(), "native-row".into()),
                    ("identifier".into(), "subject".into()),
                    ("value".into(), ISO.into()),
                    ("expiresAt".into(), expiry_date.clone()),
                    ("nested".into(), nested.clone()),
                ]) {
                    input.data(&name, value);
                }
                getter(
                    &input,
                    if name == "native-array-root" {
                        "map"
                    } else {
                        "getTime"
                    },
                    false,
                    &state,
                    |_| {
                        Err(AuthError::internal(
                            "Native verification roots must bypass JSON revival",
                        ))
                    },
                );
                let value = input.value.clone();
                roots.push(input);
                value
            }
            "native-function-root" => {
                let input = Root::new("function")?;
                getter(&input, "expiresAt", true, &state, |_| {
                    Err(AuthError::internal(
                        "Function roots must be rejected before property access",
                    ))
                });
                let value = input.value.clone();
                roots.push(input);
                value
            }
            "native-true" => true.into(),
            "native-number" => 42.into(),
            "native-infinity" => f64::INFINITY.into(),
            "native-false" => false.into(),
            "native-null" => FieldValue::Null,
            "native-undefined" => FieldValue::Undefined,
            "string-object-revival" => FieldValue::from(record()).stringify_native()?,
            "string-true" => "true".into(),
            "string-number" => "42".into(),
            "string-text" => r#""text""#.into(),
            "string-array" => "[]".into(),
            "string-null" => "null".into(),
            "string-malformed" => "{".into(),
            _ => return Err(AuthError::internal("Unknown Verification consume contract")),
        };
        roots.push(expiry);
        state.input.set(value.clone()).unwrap();
        Ok(Self {
            value,
            original,
            nested,
            child_date,
            child_function,
            expiry_date,
            state,
            _roots: roots,
        })
    }

    pub(super) fn identities(&self, result: &FieldValue) -> AuthResult<Json> {
        let property = |value: &FieldValue, name: &str| {
            if value.is_null() || value.is_undefined() {
                Ok(FieldValue::Undefined)
            } else {
                value.model_property(name)
            }
        };
        let nested = property(result, "nested")?;
        Ok(json!({
            "sameInput": result.strict_equals(&self.value), "sameNested": nested.strict_equals(&self.nested),
            "samePayload": property(result, "payload")?.strict_equals(&self.nested),
            "sameChildDate": property(&nested, "childDate")?.strict_equals(&self.child_date),
            "sameChildFunction": property(&nested, "childFunction")?.strict_equals(&self.child_function),
            "sameTopFunction": property(result, "childFunction")?.strict_equals(&self.child_function),
            "sameExpiryDate": property(result, "expiresAt")?.strict_equals(&self.expiry_date),
        }))
    }

    pub(super) fn state(&self) -> AuthResult<Json> {
        let counters = self.state.counters.lock().unwrap();
        let mutation = if matches!(
            self.value,
            FieldValue::Object(_)
                | FieldValue::Array(_)
                | FieldValue::Date(_)
                | FieldValue::Function(_)
        ) {
            self.value.model_property("mutation")?
        } else {
            FieldValue::Undefined
        };
        let mutation = self.state.observer.lock().unwrap().observe(&mutation)?;
        Ok(
            json!({"expiryReads":counters.expiry_reads,"conversionCalls":counters.conversion_calls,"mutation":mutation}),
        )
    }
}
