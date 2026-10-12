//! Replay the frozen descriptor graph without invoking accessors during observation.

use super::super::__private_core::{
    FieldObject,
    field_value::{FieldObjectSource, FieldPropertyDescriptor},
};
use super::*;

#[allow(
    dead_code,
    reason = "Only the core Memory consumer replays the accessor lane."
)]
pub(crate) fn cases(consumer: &str) -> impl Iterator<Item = &'static Json> + '_ {
    static FIXTURE: OnceLock<Json> = OnceLock::new();
    FIXTURE.get_or_init(|| {
        serde_json::from_str(include_str!(
            "../../fixtures/native-sort-getter-runtime-1.7.6.json"
        ))
        .expect("The frozen accessor observation must decode")
    })["cases"]
        .as_array()
        .unwrap()
        .iter()
        .filter(move |case| case["consumer"] == consumer)
}

struct GetterRow {
    properties: FieldObject,
    getter: FieldFunction,
}

impl FieldObjectSource for GetterRow {
    fn own_keys(&self) -> AuthResult<Vec<String>> {
        self.properties.own_keys()
    }

    fn own_property_descriptor(&self, name: &str) -> AuthResult<Option<FieldPropertyDescriptor>> {
        self.properties.own_property_descriptor(name)
    }

    fn get(&self, _: &str) -> AuthResult<Option<FieldValue>> {
        Err(AuthError::internal(
            "The source getter requires its original record receiver",
        ))
    }

    fn get_with_receiver(
        &self,
        name: &str,
        receiver: &FieldValue,
    ) -> AuthResult<Option<FieldValue>> {
        if name == "name" {
            self.getter.call_with(receiver, &[]).map(Some)
        } else {
            self.properties.get(name)
        }
    }

    fn set(&self, _: String, _: FieldValue) -> AuthResult<Option<FieldValue>> {
        Err(AuthError::TypeError(
            "Attempted to assign to readonly property.".into(),
        ))
    }

    fn delete(&self, _: &str) -> AuthResult<Option<FieldValue>> {
        Err(AuthError::internal(
            "The source sorting contract does not delete row properties",
        ))
    }

    fn snapshot_fields(&self) -> AuthResult<FieldMap> {
        Err(AuthError::internal(
            "The source sorting contract must not snapshot an accessor row",
        ))
    }

    fn identity(&self) -> usize {
        std::ptr::from_ref(self) as usize
    }
}

pub(super) fn row(mut properties: FieldMap, getter: FieldFunction) -> FieldValue {
    let _ = properties.insert("name".into(), FieldValue::Undefined);
    FieldObject::from_source(Arc::new(GetterRow {
        properties: properties.into(),
        getter,
    }))
    .into()
}

struct Graph<'a> {
    state: &'a mut State,
    identities: Vec<FieldValue>,
}

impl Graph<'_> {
    fn value(&mut self, value: &FieldValue) -> AuthResult<Json> {
        let kind = match value {
            FieldValue::Object(_) => "object",
            FieldValue::Array(_) => "array",
            FieldValue::Date(_) => "date",
            _ => return self.state.observer.observe(value),
        };
        if let Some(index) = self
            .identities
            .iter()
            .position(|known| known.strict_equals(value))
        {
            return Ok(json!({"reference": format!("object-{}", index + 1)}));
        }
        self.identities.push(value.clone());
        let identity = format!("object-{}", self.identities.len());
        let keys = match value {
            FieldValue::Array(array) => {
                let mut keys = array
                    .own_indices()?
                    .into_iter()
                    .map(|index| index.to_string())
                    .collect::<Vec<_>>();
                assert_eq!(
                    value
                        .enumerable_fields()?
                        .keys()
                        .cloned()
                        .collect::<Vec<_>>(),
                    keys,
                    "The source fixture constructs dense arrays without named properties"
                );
                keys.push("length".into());
                keys
            }
            FieldValue::Object(object) => object.own_keys()?,
            FieldValue::Date(date) => date.properties().own_keys()?,
            _ => unreachable!(),
        };
        let mut properties = Vec::new();
        for name in &keys {
            let descriptor = match value {
                FieldValue::Array(_) => FieldPropertyDescriptor {
                    enumerable: name != "length",
                },
                FieldValue::Object(object) => object.own_property_descriptor(name)?.unwrap(),
                FieldValue::Date(date) => date.properties().own_property_descriptor(name)?.unwrap(),
                _ => unreachable!(),
            };
            let accessor =
                name == "name" && self.state.rows.iter().any(|row| row.strict_equals(value));
            let property = if accessor {
                let getter: FieldValue = self.state.getter.clone().unwrap().into();
                json!({"enumerable": descriptor.enumerable, "get": self.value(&getter)?, "set": self.value(&FieldValue::Undefined)?})
            } else {
                json!({"enumerable": descriptor.enumerable, "value": self.value(&value.model_property(name)?)?})
            };
            properties.push(json!([name, property]));
        }
        let mut result =
            json!({"identity":identity,"type":kind,"ownKeys":keys,"properties":properties});
        if let FieldValue::Date(_) = value {
            result["value"] = self.state.observer.observe(value)?["value"].clone();
        }
        Ok(result)
    }
}

pub(super) fn snapshot(state: &mut State, result: Option<FieldValue>) -> AuthResult<Json> {
    let mut root = FieldMap::from([
        ("rows".into(), state.rows.clone().into()),
        ("cells".into(), state.cells.clone().into()),
    ]);
    if let Some(result) = result {
        let _ = root.insert("result".into(), result);
    }
    Graph {
        state,
        identities: Vec::new(),
    }
    .value(&root.into())
}

pub(super) fn finish(
    state: &mut State,
    before: Json,
    result: AuthResult<FieldValue>,
) -> AuthResult<Json> {
    let (outcome, result) = match result {
        Ok(value) => (json!({"returned":true}), Some(value)),
        Err(error) => {
            let value = error.into_thrown_value()?;
            (
                json!({"returned":false,"sameOriginal":value.strict_equals(&state.original),"error":{"thrown":state.observer.observe(&value)?}}),
                None,
            )
        }
    };
    let after = snapshot(state, result)?;
    Ok(
        json!({"before":before,"outcome":outcome,"after":after,"events":state.observer.events,"counts":state.counts,"functions":state.observer.function_ids()}),
    )
}
