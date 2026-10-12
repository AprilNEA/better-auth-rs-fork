//! Compare executable native observations separately from retained JavaScript reflection metadata.

use super::{AuthError, AuthResult, FieldValue};
use serde_json::{Value as Json, json};

#[path = "observation_replay.rs"]
mod replay;
pub(crate) use replay::assert_replay;

#[derive(Default)]
pub(crate) struct NativeObservation {
    pub(crate) events: Vec<Json>,
    functions: Vec<FieldValue>,
}

impl NativeObservation {
    pub(crate) fn function_ids(&self) -> Vec<String> {
        (1..=self.functions.len())
            .map(|index| format!("function-{index}"))
            .collect()
    }

    pub(crate) fn observe(&mut self, value: &FieldValue) -> AuthResult<Json> {
        Ok(match value {
            FieldValue::Undefined => json!({"type":"undefined"}),
            FieldValue::Function(_) => {
                let index = match self
                    .functions
                    .iter()
                    .position(|known| known.strict_equals(value))
                {
                    Some(index) => index,
                    None => {
                        self.functions.push(value.clone());
                        self.functions.len() - 1
                    }
                };
                json!({"type":"function","identity":format!("function-{}", index + 1)})
            }
            FieldValue::Date(date) => {
                let value = match date.to_datetime()? {
                    Some(date) => date.to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
                    None => "Invalid Date".into(),
                };
                json!({"type":"date","value":value})
            }
            FieldValue::Number(value) if !value.is_finite() => {
                let value = if value.is_nan() {
                    "NaN"
                } else if value.is_sign_negative() {
                    "-Infinity"
                } else {
                    "Infinity"
                };
                json!({"type":"number","value":value})
            }
            FieldValue::Number(value) if *value == 0.0 && value.is_sign_negative() => {
                json!({"type":"number","value":"-0"})
            }
            FieldValue::Utf16String(value) => match value.to_utf8() {
                Ok(value) => value.into(),
                Err(_) => json!({"type":"utf16","value":value.as_utf16()}),
            },
            FieldValue::Array(array) => Json::Array(
                (0..array.len()?)
                    .map(|index| {
                        array.get(index)?.map_or_else(
                            || Ok(json!({"type":"hole"})),
                            |value| self.observe(&value),
                        )
                    })
                    .collect::<AuthResult<_>>()?,
            ),
            FieldValue::Object(fields) => Json::Object(
                fields
                    .enumerable_keys()?
                    .into_iter()
                    .map(|name| {
                        let value = fields.get(&name)?.unwrap_or_default();
                        Ok((name, self.observe(&value)?))
                    })
                    .collect::<AuthResult<_>>()?,
            ),
            value => value.json()?.ok_or_else(|| {
                AuthError::internal("Native observation requires a representable primitive")
            })?,
        })
    }

    pub(crate) fn record(&mut self, phase: &str, fields: impl IntoIterator<Item = (String, Json)>) {
        let mut event = serde_json::Map::from_iter([("phase".into(), phase.into())]);
        event.extend(fields);
        self.events.push(event.into());
    }

    pub(crate) fn call(
        &mut self,
        phase: &str,
        receiver: &FieldValue,
        expected: &FieldValue,
        arguments: &[FieldValue],
    ) -> AuthResult<()> {
        let arguments = self.observe(&arguments.to_vec().into())?;
        self.record(
            phase,
            [
                (
                    "sameReceiver".into(),
                    receiver.strict_equals(expected).into(),
                ),
                ("arguments".into(), arguments),
            ],
        );
        Ok(())
    }

    pub(crate) fn outcome(
        &mut self,
        result: AuthResult<FieldValue>,
        original: &FieldValue,
    ) -> AuthResult<Json> {
        Ok(match result {
            Ok(value) => json!({"returned":true,"result":self.observe(&value)?}),
            Err(error) => {
                let error = error.into_thrown_value()?;
                json!({"returned":false,"sameOriginal":error.strict_equals(original),"error":self.observe(&error)?})
            }
        })
    }
}
