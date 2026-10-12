//! Execute the data-record lane while retaining the separate complete JavaScript reflection audit.

#![expect(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic_in_result_fn,
    clippy::panic,
    clippy::indexing_slicing,
    reason = "The successful source fixture defines valid scenario indices, callbacks, and complete observations."
)]
#![expect(
    clippy::allow_attributes,
    reason = "Consumer-specific helpers are shared between two crates, so dead-code expectations would be unfulfilled in one crate."
)]

use super::native_test_observation::{NativeObservation, assert_replay};
use super::{AuthError, AuthResult, FieldDate, FieldFunction, FieldMap, FieldValue};
use serde_json::{Map, Value as Json, json};
use std::sync::{Arc, Mutex, OnceLock, Weak};

#[path = "native_sort_contract/getters.rs"]
mod getters;
#[allow(
    unused_imports,
    reason = "The core Memory consumer replays the accessor lane."
)]
pub(crate) use getters::cases as getter_cases;

pub(crate) fn fixture() -> &'static Json {
    static FIXTURE: OnceLock<Json> = OnceLock::new();
    FIXTURE.get_or_init(|| {
        serde_json::from_str(include_str!(
            "../fixtures/native-sort-data-runtime-1.7.6.json"
        ))
        .expect("Successful source runtime fixture must decode")
    })
}

pub(crate) fn cases(consumer: &str) -> impl Iterator<Item = &'static Json> + '_ {
    fixture()["cases"]
        .as_array()
        .unwrap()
        .iter()
        .filter(move |case| case["consumer"] == consumer)
}

struct Conversion {
    receiver: FieldValue,
    id: String,
    spec: Json,
    calls: usize,
}

enum TimeValue {
    Cell(usize),
    Date(FieldValue),
}

struct TimeMethod {
    receiver: FieldValue,
    id: String,
    value: TimeValue,
}

struct State {
    consumer: String,
    scenario: Json,
    observer: NativeObservation,
    counts: Map<String, Json>,
    rows: Vec<FieldValue>,
    cells: Vec<FieldValue>,
    conversions: Vec<Conversion>,
    time_methods: Vec<TimeMethod>,
    methods: Option<[FieldValue; 3]>,
    original: FieldValue,
    getter: Option<FieldFunction>,
}

impl State {
    fn event(
        &mut self,
        phase: &str,
        fields: impl IntoIterator<Item = (String, Json)>,
    ) -> AuthResult<()> {
        let count = self.counts.get(phase).and_then(Json::as_u64).unwrap_or(0) + 1;
        self.counts.insert(phase.into(), count.into());
        self.observer.record(
            phase,
            std::iter::once(("count".into(), count.into())).chain(fields),
        );
        let mutation = self.scenario["mutate"].clone();
        if mutation["phase"] == phase && mutation["at"] == count {
            let index = mutation["target"].as_u64().unwrap() as usize;
            let id = self.cells[index].model_property("id")?.decode::<String>()?;
            let replacement = self.make_value(
                &json!({"kind":"boxed","value":mutation["value"]}),
                format!("{id}:replacement"),
            )?;
            self.cells[index].set_model_property("value", replacement.clone())?;
            if self.consumer != "jwk" && self.getter.is_none() {
                self.rows[index].set_model_property("name", replacement)?;
            }
            self.observer.record(
                "mutation",
                [
                    ("target".into(), id.into()),
                    ("replacement".into(), mutation["value"].clone()),
                ],
            );
        }
        let failure = &self.scenario["fail"];
        if failure["phase"] == phase && failure["at"] == count {
            return Err(AuthError::from_thrown(self.original.clone()));
        }
        Ok(())
    }

    fn make_value(&mut self, spec: &Json, id: String) -> AuthResult<FieldValue> {
        let methods = self.methods.as_ref().unwrap();
        match spec["kind"].as_str().unwrap() {
            "missing" => Ok(FieldValue::Undefined),
            "primitive" => primitive(&spec["value"]),
            "boxed" => {
                let receiver = FieldValue::from(FieldMap::from([
                    ("label".into(), id.clone().into()),
                    ("valueOf".into(), methods[0].clone()),
                    ("toString".into(), methods[1].clone()),
                ]));
                self.conversions.push(Conversion {
                    receiver: receiver.clone(),
                    id,
                    spec: spec.clone(),
                    calls: 0,
                });
                Ok(receiver)
            }
            "date" => {
                let value = primitive(&spec["value"])?;
                let receiver =
                    FieldValue::from(FieldDate::from_milliseconds(value.as_f64().unwrap()));
                receiver.set_model_property("getTime", methods[2].clone())?;
                self.time_methods.push(TimeMethod {
                    receiver: receiver.clone(),
                    id,
                    value: TimeValue::Date(value),
                });
                Ok(receiver)
            }
            kind => panic!("Unknown source scenario kind: {kind}"),
        }
    }

    fn method(
        &mut self,
        name: &str,
        receiver: &FieldValue,
        arguments: &[FieldValue],
    ) -> AuthResult<FieldValue> {
        assert!(
            arguments.is_empty(),
            "Source sorting methods receive no arguments"
        );
        if name == "readSortField" {
            let index = self
                .rows
                .iter()
                .position(|row| row.strict_equals(receiver))
                .unwrap();
            let id = self.cells[index].model_property("id")?;
            let field = if self.consumer == "jwk" {
                "createdAt"
            } else {
                "name"
            };
            let observed = self.observer.observe(&id)?;
            self.event(
                "read",
                [("id".into(), observed), ("field".into(), field.into())],
            )?;
            return self.cells[index].model_property(if self.consumer == "jwk" {
                "time"
            } else {
                "value"
            });
        }
        if name == "getTime" {
            let method = self
                .time_methods
                .iter()
                .find(|method| method.receiver.strict_equals(receiver))
                .unwrap();
            let id = method.id.clone();
            let cell = match &method.value {
                TimeValue::Cell(index) => Some(*index),
                TimeValue::Date(_) => None,
            };
            let date = match &method.value {
                TimeValue::Date(value) => Some(value.clone()),
                TimeValue::Cell(_) => None,
            };
            self.event(
                "get-time",
                [("id".into(), id.into()), ("arguments".into(), json!([]))],
            )?;
            return match cell {
                Some(index) => self.cells[index].model_property("value"),
                None => Ok(date.unwrap()),
            };
        }
        let conversion = self
            .conversions
            .iter_mut()
            .find(|conversion| conversion.receiver.strict_equals(receiver))
            .unwrap();
        conversion.calls += 1;
        let ordinal = conversion.calls;
        let id = conversion.id.clone();
        let spec = &conversion.spec;
        let result = primitive(if ordinal % 2 == 0 && spec.get("alternate").is_some() {
            &spec["alternate"]
        } else {
            &spec["value"]
        })?;
        let observed = self.observer.observe(&result)?;
        self.event(
            "convert",
            [
                ("id".into(), id.into()),
                ("method".into(), name.into()),
                ("ordinal".into(), ordinal.into()),
                ("arguments".into(), json!([])),
                ("result".into(), observed),
            ],
        )?;
        if name == "toString" {
            Ok(result.display_utf16()?.into())
        } else {
            Ok(result)
        }
    }

    fn snapshot(&mut self) -> AuthResult<Json> {
        self.observer.observe(
            &FieldMap::from([
                ("rows".into(), self.rows.clone().into()),
                ("cells".into(), self.cells.clone().into()),
            ])
            .into(),
        )
    }
}

fn primitive(value: &Json) -> AuthResult<FieldValue> {
    match value.get("type").and_then(Json::as_str) {
        Some("undefined") => Ok(FieldValue::Undefined),
        Some("number") if value["value"] == "NaN" => Ok(f64::NAN.into()),
        None => FieldValue::from_json(value.clone()),
        _ => panic!("Unknown source primitive: {value}"),
    }
}

#[derive(Clone)]
pub(crate) struct Harness(Arc<Mutex<State>>);

impl Harness {
    pub(crate) fn new(case: &Json) -> AuthResult<Self> {
        Self::build(case, false)
    }

    #[allow(
        dead_code,
        reason = "The core Memory consumer replays the accessor lane."
    )]
    pub(crate) fn new_getters(case: &Json) -> AuthResult<Self> {
        Self::build(case, true)
    }

    fn build(case: &Json, accessors: bool) -> AuthResult<Self> {
        let consumer = case["consumer"].as_str().unwrap();
        let scenario = fixture()["scenarios"]
            .as_array()
            .unwrap()
            .iter()
            .find(|scenario| scenario["name"] == case["scenario"])
            .unwrap()
            .clone();
        let original = FieldMap::from([
            ("kind".into(), "native-sort-failure".into()),
            ("consumer".into(), consumer.into()),
            ("scenario".into(), scenario["name"].as_str().unwrap().into()),
        ])
        .into();
        let state = Arc::new(Mutex::new(State {
            consumer: consumer.into(),
            scenario: scenario.clone(),
            observer: NativeObservation::default(),
            counts: Map::new(),
            rows: Vec::new(),
            cells: Vec::new(),
            conversions: Vec::new(),
            time_methods: Vec::new(),
            methods: None,
            original,
            getter: None,
        }));
        let methods = ["valueOf", "toString", "getTime"].map(|name| {
            let state: Weak<Mutex<State>> = Arc::downgrade(&state);
            FieldFunction::contextual(move |receiver, arguments| {
                state
                    .upgrade()
                    .unwrap()
                    .lock()
                    .unwrap()
                    .method(name, receiver, arguments)
            })
            .into()
        });
        let mut current = state.lock().unwrap();
        current.methods = Some(methods);
        if accessors {
            let weak = Arc::downgrade(&state);
            current.getter = Some(FieldFunction::contextual(move |receiver, arguments| {
                weak.upgrade()
                    .unwrap()
                    .lock()
                    .unwrap()
                    .method("readSortField", receiver, arguments)
            }));
        }
        for (index, spec) in scenario["values"].as_array().unwrap().iter().enumerate() {
            let id = format!("row-{index}");
            let value = current.make_value(spec, id.clone())?;
            let mut cell = FieldMap::from([
                ("id".into(), id.clone().into()),
                ("value".into(), value.clone()),
            ]);
            let mut row = FieldMap::from([("id".into(), id.clone().into())]);
            if consumer == "jwk" {
                let time: FieldValue = FieldMap::from([
                    ("label".into(), id.clone().into()),
                    (
                        "getTime".into(),
                        current.methods.as_ref().unwrap()[2].clone(),
                    ),
                ])
                .into();
                current.time_methods.push(TimeMethod {
                    receiver: time.clone(),
                    id,
                    value: TimeValue::Cell(index),
                });
                let expiry = if scenario["keyring"] == true && index == 1 {
                    FieldDate::from_milliseconds(0.0).into()
                } else {
                    FieldValue::Null
                };
                let algorithm: FieldValue = if scenario["keyring"] == true && index == 2 {
                    "RS256".into()
                } else if index % 2 == 0 {
                    "EdDSA".into()
                } else {
                    FieldValue::Null
                };
                cell.extend([
                    ("time".into(), time.clone()),
                    ("expiry".into(), expiry.clone()),
                    ("algorithm".into(), algorithm.clone()),
                ]);
                row.extend([
                    ("alg".into(), algorithm),
                    ("expiresAt".into(), expiry),
                    ("createdAt".into(), time),
                ]);
            } else if spec["kind"] != "missing" {
                row.insert("name".into(), value);
            }
            current.cells.push(cell.into());
            let row = match &current.getter {
                Some(getter) if spec["kind"] != "missing" => getters::row(row, getter.clone()),
                _ => row.into(),
            };
            current.rows.push(row);
        }
        drop(current);
        Ok(Self(state))
    }

    pub(crate) fn rows(&self) -> Vec<FieldValue> {
        self.0.lock().unwrap().rows.clone()
    }

    #[allow(
        dead_code,
        reason = "Only the core Memory consumer binds adapter-owned row handles."
    )]
    pub(crate) fn bind_rows(&self, rows: Vec<FieldValue>) {
        self.0.lock().unwrap().rows = rows;
    }

    pub(crate) fn before(&self) -> AuthResult<Json> {
        let mut state = self.0.lock().unwrap();
        if state.getter.is_some() {
            getters::snapshot(&mut state, None)
        } else {
            state.snapshot()
        }
    }

    #[allow(
        dead_code,
        reason = "Only the core Memory consumer applies a schema output callback."
    )]
    pub(crate) fn output(&self, value: FieldValue) -> AuthResult<FieldValue> {
        let mut state = self.0.lock().unwrap();
        let observed = if state.getter.is_some()
            && matches!(
                value,
                FieldValue::Array(_) | FieldValue::Object(_) | FieldValue::Date(_)
            ) {
            "native-object".into()
        } else {
            state.observer.observe(&value)?
        };
        state.event("output", [("value".into(), observed)])?;
        Ok(value)
    }

    pub(crate) fn finish(&self, before: Json, result: AuthResult<FieldValue>) -> AuthResult<Json> {
        let mut state = self.0.lock().unwrap();
        if state.getter.is_some() {
            return getters::finish(&mut state, before, result);
        }
        let returned = result.as_ref().ok().cloned();
        let original = state.original.clone();
        let mut outcome = state.observer.outcome(result, &original)?;
        if let Some(error) = outcome.get_mut("error") {
            *error = json!({"thrown":error.take()});
        }
        let after = state.snapshot()?;
        let returned_rows = match returned {
            Some(value) if state.consumer == "jwk" => {
                if value.is_undefined() {
                    Vec::new()
                } else {
                    vec![value]
                }
            }
            Some(value) => value.as_array().unwrap().snapshot()?,
            None => Vec::new(),
        };
        let field = if state.consumer == "jwk" {
            "createdAt"
        } else {
            "name"
        };
        let cell_field = if state.consumer == "jwk" {
            "time"
        } else {
            "value"
        };
        let identities = returned_rows.iter().map(|row| {
            let value = row.model_property(field)?;
            let mut values = Vec::new();
            if matches!(value, FieldValue::Object(_) | FieldValue::Array(_) | FieldValue::Date(_)) {
                for (index, cell) in state.cells.iter().enumerate() {
                    if value.strict_equals(&cell.model_property(cell_field)?) { values.push(index); }
                }
            }
            Ok(json!({"storedRecord":state.rows.iter().position(|stored| stored.strict_equals(row)).map_or(-1, |index| index as i64),"valueCells":values}))
        }).collect::<AuthResult<Vec<_>>>()?;
        Ok(json!({
            "before":before, "outcome":outcome, "after":after,
            "events":state.observer.events, "counts":state.counts,
            "identities":identities, "functions":state.observer.function_ids(),
        }))
    }
}

pub(crate) fn assert_case(actual: &Json, case: &Json) {
    let label = format!(
        "{}/{}/{}",
        case["consumer"], case["scenario"], case["direction"]
    );
    assert_replay(actual, &case["runtime"], &label);
}

/// The typed selection boundary does not retain the custom adapter's top-level object handle.
#[allow(
    dead_code,
    reason = "The shared harness is also compiled by core, which has no JWT plugin."
)]
pub(crate) fn assert_jwk_selection(actual: &Json, case: &Json) {
    let expected = &case["runtime"];
    let label = format!(
        "jwk/{}/{}/{}",
        case["scenario"], case["lane"], case["algorithm"]
    );
    for section in ["before", "outcome", "after", "functions"] {
        assert_replay(
            &actual[section],
            &expected[section],
            &format!("{label}/{section}"),
        );
    }
    let events = expected["events"].as_array().unwrap();
    assert!(matches!(
        events[0]["phase"].as_str(),
        Some("keyring-read" | "adapter-read")
    ));
    assert_replay(
        &actual["events"],
        &Json::Array(events[1..].to_vec()),
        &format!("{label}/comparison-events"),
    );
    let counts = expected["counts"].as_object().unwrap();
    let comparison_counts = counts
        .iter()
        .filter(|(name, _)| !matches!(name.as_str(), "keyring-read" | "adapter-read"))
        .map(|(name, count)| (name.clone(), count.clone()))
        .collect::<Map<_, _>>();
    assert_replay(
        &actual["counts"],
        &comparison_counts.into(),
        &format!("{label}/comparison-counts"),
    );
    let actual_ids = actual["identities"].as_array().unwrap();
    let expected_ids = expected["identities"].as_array().unwrap();
    assert_eq!(
        actual_ids.len(),
        expected_ids.len(),
        "{label}/returned identity count"
    );
    for (actual, expected) in actual_ids.iter().zip(expected_ids) {
        assert_replay(
            &actual["valueCells"],
            &expected["valueCells"],
            &format!("{label}/createdAt-identity"),
        );
        assert_eq!(
            actual["storedRecord"], -1,
            "The typed boundary must not masquerade as a native record handle"
        );
    }
}
