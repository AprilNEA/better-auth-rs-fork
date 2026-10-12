//! Ordered defaults merging for native own string properties.
//! Prototype chains and symbol properties require an embedding that exposes those operations.

use crate::{AuthResult, FieldMap, FieldObject, FieldValue};

#[cfg(test)]
#[path = "defu_tests.rs"]
mod tests;

/// Merge defaults from left to right. Earlier non-nullish values take precedence.
/// Read each default object before the preceding values, concatenate arrays, and recurse into objects.
pub fn defu(values: &[FieldValue]) -> AuthResult<FieldValue> {
    values
        .iter()
        .try_fold(FieldMap::new().into(), |base, defaults| {
            merge(&base, defaults)
        })
        .map(FieldValue::Object)
}

fn merge(base: &FieldObject, defaults: &FieldValue) -> AuthResult<FieldObject> {
    let mut output = if matches!(defaults, FieldValue::Object(_)) {
        defaults.enumerable_fields()?
    } else {
        FieldMap::new()
    };
    for name in base.own_keys()? {
        if matches!(name.as_str(), "__proto__" | "constructor")
            || !base
                .own_property_descriptor(&name)?
                .is_some_and(|field| field.enumerable)
        {
            continue;
        }
        let value = base.get(&name)?.unwrap_or_default();
        if value.is_null() || value.is_undefined() {
            continue;
        }
        let value = match (value, output.get(&name)) {
            (FieldValue::Array(base), Some(FieldValue::Array(defaults))) => {
                let mut values = base.snapshot()?;
                values.extend(defaults.snapshot()?);
                values.into()
            }
            (FieldValue::Object(base), Some(defaults @ FieldValue::Object(_))) => {
                FieldValue::Object(merge(&base, defaults)?)
            }
            (value, _) => value,
        };
        let _ = output.insert(name, value);
    }
    Ok(output.into())
}
