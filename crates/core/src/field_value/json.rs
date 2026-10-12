//! Prepare each property once before emitting JSON text or a UTF-8 JSON value.

#[cfg(test)]
#[path = "json_tests.rs"]
mod tests;

use super::{ContainerIdentity, FieldDate, FieldMap, FieldObject, FieldValue, PrimitiveHint};
use crate::{AuthError, AuthResult};
use serde::{Serialize, ser::SerializeMap};
use std::{
    cell::RefCell,
    collections::{HashMap, HashSet},
};

pub(crate) struct Json<'a>(pub(crate) &'a FieldValue);

impl Serialize for Json<'_> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let state = JsonState::default();
        let value = state
            .prepare("", self.0, None)
            .map_err(|error| state.error(error))?;
        JsonNode(&value, &state).serialize(serializer)
    }
}

#[derive(Default)]
enum Output {
    #[default]
    Text,
    Value,
}

#[derive(Clone, Copy, Default)]
enum Preparation {
    #[default]
    Json,
    Input,
}

#[derive(Default)]
struct JsonState {
    output: Output,
    preparation: Preparation,
    active: RefCell<HashSet<JsonIdentity>>,
    source_error: RefCell<Option<AuthError>>,
    http_references: Option<RefCell<HttpReferences>>,
}

impl JsonState {
    fn prepare(
        &self,
        key: &str,
        value: &FieldValue,
        holder: Option<JsonIdentity>,
    ) -> AuthResult<PreparedJson> {
        let prepared = match value {
            FieldValue::Object(_) | FieldValue::Array(_) | FieldValue::Function(_)
                if matches!(self.preparation, Preparation::Json) =>
            {
                match value.model_property("toJSON")? {
                    FieldValue::Function(method) => method.call_with(value, &[key.into()])?,
                    _ => value.clone(),
                }
            }
            FieldValue::Date(date) => {
                let own = if matches!(self.preparation, Preparation::Json) {
                    date.properties().get_with_receiver("toJSON", value)?
                } else {
                    None
                };
                match own {
                    Some(FieldValue::Function(method)) => method.call_with(value, &[key.into()])?,
                    Some(_) => value.clone(),
                    None if matches!(self.preparation, Preparation::Json) => {
                        default_date_json(date, value)?
                    }
                    None => date
                        .iso_string()?
                        .map_or(FieldValue::Null, FieldValue::String),
                }
            }
            _ => value.clone(),
        };
        let prepared = match &self.http_references {
            Some(references) => references.borrow_mut().replace(prepared, holder),
            None => prepared,
        };
        Ok(PreparedJson(prepared))
    }

    fn error<E: serde::ser::Error>(&self, error: AuthError) -> E {
        let serialized = E::custom(&error);
        *self.source_error.borrow_mut() = Some(error);
        serialized
    }

    fn recover<T>(self, result: Result<T, serde_json::Error>) -> AuthResult<T> {
        result.map_err(|error| self.source_error.into_inner().unwrap_or(error.into()))
    }
}

fn default_date_json(date: &FieldDate, receiver: &FieldValue) -> AuthResult<FieldValue> {
    if matches!(receiver.primitive(PrimitiveHint::Number)?, FieldValue::Number(value) if !value.is_finite())
    {
        return Ok(FieldValue::Null);
    }
    match date
        .properties()
        .get_with_receiver("toISOString", receiver)?
    {
        Some(FieldValue::Function(method)) => method.call_with(receiver, &[]),
        Some(_) => Err(AuthError::type_error("toISOString is not a function")),
        None => date
            .iso_string()?
            .map(FieldValue::String)
            .ok_or_else(|| AuthError::RangeError("Invalid Date".into())),
    }
}

struct PreparedJson(FieldValue);

pub(super) fn stringify(value: &FieldValue) -> AuthResult<Option<String>> {
    stringify_with_state(value, JsonState::default())
}

pub(crate) fn stringify_http(value: &FieldValue) -> AuthResult<Option<String>> {
    stringify_with_state(
        value,
        JsonState {
            http_references: Some(RefCell::default()),
            ..JsonState::default()
        },
    )
}

fn stringify_with_state(value: &FieldValue, state: JsonState) -> AuthResult<Option<String>> {
    let value = state.prepare("", value, None)?;
    if value.0.is_json_omitted() {
        return Ok(None);
    }
    let result = serde_json::to_string(&JsonNode(&value, &state));
    state.recover(result).map(Some)
}

pub(super) fn to_value(value: &FieldValue) -> AuthResult<Option<serde_json::Value>> {
    value_with_preparation(value, Preparation::Json)
}

pub(crate) fn project_input_json(value: &FieldValue) -> AuthResult<Option<serde_json::Value>> {
    value_with_preparation(value, Preparation::Input)
}

fn value_with_preparation(
    value: &FieldValue,
    preparation: Preparation,
) -> AuthResult<Option<serde_json::Value>> {
    let state = JsonState {
        output: Output::Value,
        preparation,
        ..JsonState::default()
    };
    let value = state.prepare("", value, None)?;
    if value.0.is_json_omitted() {
        return Ok(None);
    }
    let result = serde_json::to_value(JsonNode(&value, &state));
    state.recover(result).map(Some)
}

pub(super) fn project_map(
    fields: &FieldMap,
) -> AuthResult<serde_json::Map<String, serde_json::Value>> {
    let state = JsonState {
        output: Output::Value,
        ..JsonState::default()
    };
    let result = serde_json::to_value(JsonFields(fields, &state));
    match state.recover(result)? {
        serde_json::Value::Object(fields) => Ok(fields),
        _ => Err(AuthError::internal(
            "Field projection did not produce a JSON object",
        )),
    }
}

pub(super) fn serialize_fields<S: serde::Serializer>(
    fields: &FieldMap,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    JsonFields(fields, &JsonState::default()).serialize(serializer)
}

struct JsonNode<'a>(&'a PreparedJson, &'a JsonState);

impl Serialize for JsonNode<'_> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match &self.0.0 {
            FieldValue::Undefined | FieldValue::Null | FieldValue::Function(_) => {
                serializer.serialize_unit()
            }
            FieldValue::Bool(value) => value.serialize(serializer),
            FieldValue::String(value) => value.serialize(serializer),
            FieldValue::Utf16String(value) => match self.1.output {
                Output::Text => value.serialize(serializer),
                Output::Value => value
                    .to_utf8()
                    .map_err(|error| {
                        self.1.error(AuthError::internal(format!(
                            "JSON value cannot represent unpaired UTF-16 surrogates: {error}"
                        )))
                    })?
                    .serialize(serializer),
            },
            FieldValue::Number(value) if !value.is_finite() => serializer.serialize_unit(),
            FieldValue::Number(value) => {
                serde_json::value::RawValue::from_string(crate::schema_value::number_string(*value))
                    .map_err(serde::ser::Error::custom)?
                    .serialize(serializer)
            }
            // A Date returned by toJSON is emitted without invoking its method again.
            FieldValue::Date(date) => serialize_properties(
                date.properties(),
                &self.0.0,
                JsonIdentity::Date(std::sync::Arc::as_ptr(&date.0) as usize),
                self.1,
                serializer,
            ),
            FieldValue::Array(values) => {
                use serde::ser::SerializeSeq;
                let identity = ContainerIdentity::Array(values.identity());
                if !self
                    .1
                    .active
                    .borrow_mut()
                    .insert(JsonIdentity::Container(identity))
                {
                    return Err(self.1.error(AuthError::type_error(
                        "Converting circular structure to JSON",
                    )));
                }
                let result = (|| {
                    let length = values.len().map_err(|error| self.1.error(error))?;
                    let mut sequence = serializer.serialize_seq(Some(length))?;
                    for index in 0..length {
                        let value = values
                            .get(index)
                            .map_err(|error| self.1.error(error))?
                            .unwrap_or_default();
                        let value = self
                            .1
                            .prepare(
                                &index.to_string(),
                                &value,
                                Some(JsonIdentity::Container(identity)),
                            )
                            .map_err(|error| self.1.error(error))?;
                        sequence.serialize_element(&JsonNode(&value, self.1))?;
                    }
                    sequence.end()
                })();
                let _ = self
                    .1
                    .active
                    .borrow_mut()
                    .remove(&JsonIdentity::Container(identity));
                result
            }
            FieldValue::Object(object) => serialize_properties(
                object,
                &self.0.0,
                JsonIdentity::Container(ContainerIdentity::Object(object.identity())),
                self.1,
                serializer,
            ),
        }
    }
}

fn serialize_properties<S: serde::Serializer>(
    object: &FieldObject,
    receiver: &FieldValue,
    identity: JsonIdentity,
    state: &JsonState,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    if !state.active.borrow_mut().insert(identity) {
        return Err(state.error(AuthError::type_error(
            "Converting circular structure to JSON",
        )));
    }
    let result = (|| {
        let keys = object
            .enumerable_keys()
            .map_err(|error| state.error(error))?;
        let mut output = serializer.serialize_map(None)?;
        for name in keys {
            let value = object
                .get_with_receiver(&name, receiver)
                .map_err(|error| state.error(error))?
                .unwrap_or_default();
            serialize_entry(&mut output, &name, &value, state, Some(identity))?;
        }
        output.end()
    })();
    let _ = state.active.borrow_mut().remove(&identity);
    result
}

fn serialize_entry<S: SerializeMap>(
    output: &mut S,
    name: &str,
    value: &FieldValue,
    state: &JsonState,
    holder: Option<JsonIdentity>,
) -> Result<(), S::Error> {
    let value = state
        .prepare(name, value, holder)
        .map_err(|error| state.error(error))?;
    if !value.0.is_json_omitted() {
        output.serialize_entry(name, &JsonNode(&value, state))?;
    }
    Ok(())
}

struct JsonFields<'a>(&'a FieldMap, &'a JsonState);

impl Serialize for JsonFields<'_> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut fields: Vec<_> = self.0.iter().collect();
        fields.sort_by_key(|(name, _)| {
            crate::utils::json::array_index(name).map_or((true, 0), |index| (false, index))
        });
        let mut output = serializer.serialize_map(None)?;
        for (name, value) in fields {
            serialize_entry(&mut output, name, value, self.1, None)?;
        }
        output.end()
    }
}

#[derive(Clone, Copy, Hash, PartialEq, Eq)]
enum JsonIdentity {
    Container(ContainerIdentity),
    Date(usize),
}

impl JsonIdentity {
    fn of(value: &FieldValue) -> Option<Self> {
        match value {
            FieldValue::Object(object) => Some(Self::Container(ContainerIdentity::Object(
                object.identity(),
            ))),
            FieldValue::Array(array) => {
                Some(Self::Container(ContainerIdentity::Array(array.identity())))
            }
            FieldValue::Date(date) => Some(Self::Date(std::sync::Arc::as_ptr(&date.0) as usize)),
            _ => None,
        }
    }
}

#[derive(Default)]
struct HttpReferences {
    objects: HashMap<JsonIdentity, HttpReference>,
}

struct HttpReference {
    parent: Option<JsonIdentity>,
    id: usize,
    // Retain temporary method results so allocator reuse cannot conflate different objects.
    _value: FieldValue,
}

impl HttpReferences {
    fn replace(&mut self, value: FieldValue, holder: Option<JsonIdentity>) -> FieldValue {
        let Some(identity) = JsonIdentity::of(&value) else {
            return value;
        };
        let mut ancestor = holder;
        while let Some(entry) = ancestor.and_then(|current| self.objects.get(&current)) {
            if ancestor == Some(identity) {
                return format!("[Circular ref-{}]", entry.id).into();
            }
            ancestor = entry.parent;
        }
        let next_id = self.objects.len();
        let _ = self
            .objects
            .entry(identity)
            .and_modify(|entry| entry.parent = holder)
            .or_insert_with(|| HttpReference {
                parent: holder,
                id: next_id,
                _value: value.clone(),
            });
        value
    }
}
