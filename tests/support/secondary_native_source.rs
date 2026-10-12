//! Select executable values without changing the frozen source observations.

use super::{AuthError, AuthResult};
use serde_json::{Value as Json, json};

/// Select the executable value boundary from a complete descriptor snapshot.
/// Reflection flags remain in the frozen source; unsupported shapes fail explicitly.
pub(crate) fn source_value(source: &Json) -> AuthResult<Json> {
    if source.get("reference").is_some() {
        return Err(AuthError::internal(
            "Source value projection cannot discard shared references",
        ));
    }
    if source.get("identity").is_none() {
        return Ok(source.clone());
    }
    let keys = source["ownKeys"]
        .as_array()
        .ok_or_else(|| AuthError::internal("Source snapshot has no own keys"))?;
    let properties = source["properties"]
        .as_array()
        .ok_or_else(|| AuthError::internal("Source snapshot has no descriptors"))?;
    if keys.len() != properties.len()
        || keys
            .iter()
            .zip(properties)
            .any(|(key, property)| key != &property[0])
    {
        return Err(AuthError::internal(
            "Source descriptors must preserve complete own key order",
        ));
    }
    let kind = source["type"]
        .as_str()
        .ok_or_else(|| AuthError::internal("Source snapshot has no type"))?;
    if kind == "date" {
        if !keys.is_empty() {
            return Err(AuthError::internal(
                "Native Date observation cannot discard own properties",
            ));
        }
        return Ok(json!({"type":"date","value":source["value"]}));
    }
    let mut object = serde_json::Map::new();
    let mut array = Vec::new();
    let mut length = None;
    for property in properties {
        let name = property[0].as_str().ok_or_else(|| {
            AuthError::internal("Native observation cannot discard symbol properties")
        })?;
        let descriptor = &property[1];
        let value = descriptor.get("value").ok_or_else(|| {
            AuthError::internal("Native observation cannot execute a source accessor")
        })?;
        if kind == "array" && name == "length" {
            length = value.as_u64();
            continue;
        }
        if descriptor["enumerable"] != true {
            return Err(AuthError::internal(
                "Native observation cannot discard a non-enumerable property",
            ));
        }
        let value = source_value(value)?;
        match kind {
            "object" => {
                let _ = object.insert(name.into(), value);
            }
            "array" if name == array.len().to_string() => array.push(value),
            _ => {
                return Err(AuthError::internal(
                    "Source value projection requires an object or dense array without named properties",
                ));
            }
        }
    }
    match kind {
        "object" => Ok(object.into()),
        "array" if length == Some(array.len() as u64) => Ok(array.into()),
        _ => Err(AuthError::internal(
            "Source array length does not match its complete indexed properties",
        )),
    }
}
