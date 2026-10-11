use super::*;

pub(super) fn native(value: &FieldValue) -> AuthResult<Value> {
    match value {
        FieldValue::Undefined => Ok(json!({"type": "undefined"})),
        FieldValue::Date(date) => Ok(
            json!({"type": "date", "value": if date.milliseconds().is_nan() {
            Value::String("Invalid Date".into())
        } else { value.json()?.unwrap() }}),
        ),
        FieldValue::Number(number) if !number.is_finite() => Ok(json!({"type": "number", "value":
            if number.is_nan() { "NaN" } else if number.is_sign_positive() { "Infinity" } else { "-Infinity" }
        })),
        FieldValue::Array(values) => values.iter()?.map(|value| native(&value?)).collect(),
        FieldValue::Object(_) => {
            let entries = value.enumerable_fields()?;
            Ok(Value::Object(
                entries
                    .iter()
                    .map(|(key, value)| Ok((key.clone(), native(value)?)))
                    .collect::<AuthResult<_>>()?,
            ))
        }
        FieldValue::Function(_) => Err(AuthError::internal(
            "Unexpected function in native profile observation",
        )),
        _ => Ok(value.json()?.unwrap()),
    }
}

pub(super) fn error_value(error: &AuthError, state: &State) -> AuthResult<Value> {
    let observed = if let Some(value) = error.raw_value() {
        let name = value.model_property("name")?.json()?.unwrap();
        let message = value.model_property("message")?.json()?.unwrap();
        let keys = value.as_object().unwrap().enumerable_keys()?;
        let properties = native(value)?;
        json!({"name": name, "message": message,
            "keys": keys, "properties": properties})
    } else {
        let (name, message) = match error {
            AuthError::TypeError(message) => ("TypeError", message.clone()),
            AuthError::RangeError(message) => ("RangeError", message.clone()),
            AuthError::Internal(message) => ("Error", message.clone()),
            _ => ("Error", error.to_string()),
        };
        json!({"name": name, "message": message, "keys": [], "properties": {}})
    };
    Ok(
        json!({"error": observed, "originalError": error.raw_value().is_some_and(|value| value.strict_equals(&state.failure))}),
    )
}

fn attempt(read: impl FnOnce() -> AuthResult<Value>, state: &State) -> AuthResult<Value> {
    Ok(match read() {
        Ok(value) => json!({"returned": true, "value": value}),
        Err(error) => {
            let mut value = json!({"returned": false});
            value
                .as_object_mut()
                .unwrap()
                .extend(error_value(&error, state)?.as_object().unwrap().clone());
            value
        }
    })
}

fn key_order(value: &FieldValue, path: Vec<String>) -> AuthResult<Vec<Value>> {
    let keys = match value {
        FieldValue::Object(object) => object.enumerable_keys()?,
        FieldValue::Array(array) => (0..array.len()?).map(|index| index.to_string()).collect(),
        _ => return Ok(Vec::new()),
    };
    let mut order = vec![json!({"path": path, "keys": keys})];
    for key in keys {
        let mut child_path = path.clone();
        child_path.push(key.clone());
        order.extend(key_order(&value.model_property(&key)?, child_path)?);
    }
    Ok(order)
}

pub(super) fn complete(value: &FieldValue, state: &State, label: &str) -> AuthResult<Value> {
    let previous = state.log.phase(&format!("{label}:native"));
    let observed = attempt(|| native(value), state);
    state.log.phase(&format!("{label}:json"));
    let json = attempt(
        || {
            Ok(match value.json()? {
                Some(value) => json!({"defined": true, "value": value}),
                None => json!({"defined": false}),
            })
        },
        state,
    );
    state.log.phase(&format!("{label}:keys"));
    let keys = attempt(|| Ok(Value::Array(key_order(value, Vec::new())?)), state);
    state.log.phase(&previous);
    Ok(json!({"native": observed?, "json": json?, "keyOrder": keys?}))
}

pub(super) fn replace_generated(value: Value, replacements: &HashMap<String, String>) -> Value {
    match value {
        Value::String(string) => replacements
            .get(&string)
            .cloned()
            .map(Value::String)
            .unwrap_or(Value::String(string)),
        Value::Array(array) => array
            .into_iter()
            .map(|value| replace_generated(value, replacements))
            .collect(),
        Value::Object(object) => Value::Object(
            object
                .into_iter()
                .map(|(key, value)| (key, replace_generated(value, replacements)))
                .collect(),
        ),
        value => value,
    }
}
