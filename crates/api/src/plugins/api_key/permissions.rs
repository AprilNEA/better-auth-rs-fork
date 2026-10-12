use better_auth_core::query::field_string_units;
use better_auth_core::utils::json::{array_index, safe_parse_field};
use better_auth_core::{AuthError, AuthResult, FieldValue, Utf16String};

pub(super) fn check_permissions(
    key_permissions: &FieldValue,
    required: &FieldValue,
) -> AuthResult<bool> {
    let permissions = safe_parse_field(key_permissions)?;
    if !permissions.is_truthy() {
        return Ok(false);
    }
    let required = required.enumerable_fields()?;
    for (resource, requested) in &required {
        let Some(allowed) = property(&permissions, resource)?.filter(AllowedActions::is_truthy)
        else {
            return Ok(false);
        };
        let (actions, any) = if let Some(actions) = requested.as_array() {
            (Some(actions.clone()), false)
        } else if requested.is_object() || requested.as_date().is_some() {
            let actions = requested.model_property("actions")?;
            let connector = requested.model_property("connector")?;
            (
                actions.as_array().cloned(),
                connector.strict_equals(&"OR".into()),
            )
        } else {
            return Err(AuthError::internal("Invalid access control request"));
        };
        let Some(actions) = actions else {
            return Ok(false);
        };
        if actions.len()? == 0 {
            return Ok(false);
        }
        let includes = |action: &FieldValue| {
            if action.is_string() {
                allowed.includes(action)
            } else {
                Ok(false)
            }
        };
        let authorized = if any {
            !actions.every(|action| includes(action).map(|included| !included))?
        } else {
            actions.every(includes)?
        };
        if !authorized {
            return Ok(false);
        }
    }
    Ok(!required.is_empty())
}

// Upstream reads ordinary properties, including inherited methods, before calling includes.
// These variants retain that observation without fabricating JavaScript function properties.
enum AllowedActions {
    Value(FieldValue),
    TruthyWithoutIncludes,
    StringPrototype,
}

impl AllowedActions {
    fn is_truthy(&self) -> bool {
        match self {
            Self::Value(value) => value.is_truthy(),
            Self::TruthyWithoutIncludes | Self::StringPrototype => true,
        }
    }

    fn includes(&self, action: &FieldValue) -> AuthResult<bool> {
        match self {
            Self::Value(FieldValue::Array(values)) => values.includes(action),
            Self::StringPrototype => Ok(action.display_utf16()?.as_utf16().is_empty()),
            Self::Value(value) => {
                let units = field_string_units(value).ok_or_else(includes_error)?;
                let action = action.display_utf16()?;
                let action = action.as_utf16();
                Ok(action.is_empty() || units.windows(action.len()).any(|units| units == action))
            }
            _ => Err(includes_error()),
        }
    }
}

fn includes_error() -> AuthError {
    AuthError::internal("allowedActions.includes is not a function")
}

fn property(permissions: &FieldValue, name: &str) -> AuthResult<Option<AllowedActions>> {
    match permissions {
        FieldValue::Object(fields) => {
            if let Some(value) = fields.get(name)? {
                return Ok(Some(AllowedActions::Value(value)));
            }
        }
        FieldValue::Array(values) => {
            if name == "length" {
                return Ok(Some(AllowedActions::Value((values.len()? as f64).into())));
            }
            if let Some(index) = array_index(name) {
                return Ok(values.get(index as usize)?.map(AllowedActions::Value));
            }
        }
        FieldValue::String(_) | FieldValue::Utf16String(_) => {
            let Some(units) = field_string_units(permissions) else {
                return Ok(None);
            };
            if name == "length" {
                return Ok(Some(AllowedActions::Value((units.len() as f64).into())));
            }
            if let Some(index) = array_index(name) {
                return Ok(units.get(index as usize).map(|unit| {
                    AllowedActions::Value(Utf16String::from_units(vec![*unit]).into())
                }));
            }
        }
        FieldValue::Function(_) => {
            return Err(AuthError::internal(
                "JavaScript function properties are unavailable for this Rust field callback",
            ));
        }
        FieldValue::Null | FieldValue::Undefined => return Ok(None),
        FieldValue::Bool(_) | FieldValue::Number(_) | FieldValue::Date(_) => {}
    }
    if name == "__proto__" {
        return Ok(Some(match permissions {
            FieldValue::Array(_) => AllowedActions::Value(Vec::<FieldValue>::new().into()),
            FieldValue::String(_) | FieldValue::Utf16String(_) => AllowedActions::StringPrototype,
            _ => AllowedActions::TruthyWithoutIncludes,
        }));
    }
    Ok(inherited_method(permissions, name).then_some(AllowedActions::TruthyWithoutIncludes))
}

fn inherited_method(value: &FieldValue, name: &str) -> bool {
    if matches!(
        name,
        "constructor"
            | "toString"
            | "toLocaleString"
            | "valueOf"
            | "hasOwnProperty"
            | "isPrototypeOf"
            | "propertyIsEnumerable"
            | "__defineGetter__"
            | "__defineSetter__"
            | "__lookupGetter__"
            | "__lookupSetter__"
    ) {
        return true;
    }
    match value {
        FieldValue::Array(_) => matches!(
            name,
            "at" | "concat"
                | "copyWithin"
                | "entries"
                | "every"
                | "fill"
                | "filter"
                | "find"
                | "findIndex"
                | "findLast"
                | "findLastIndex"
                | "flat"
                | "flatMap"
                | "forEach"
                | "includes"
                | "indexOf"
                | "join"
                | "keys"
                | "lastIndexOf"
                | "map"
                | "pop"
                | "push"
                | "reduce"
                | "reduceRight"
                | "reverse"
                | "shift"
                | "slice"
                | "some"
                | "sort"
                | "splice"
                | "toReversed"
                | "toSorted"
                | "toSpliced"
                | "unshift"
                | "values"
                | "with"
        ),
        FieldValue::String(_) | FieldValue::Utf16String(_) => matches!(
            name,
            "anchor"
                | "at"
                | "big"
                | "blink"
                | "bold"
                | "charAt"
                | "charCodeAt"
                | "codePointAt"
                | "concat"
                | "endsWith"
                | "fixed"
                | "fontcolor"
                | "fontsize"
                | "includes"
                | "indexOf"
                | "isWellFormed"
                | "italics"
                | "lastIndexOf"
                | "link"
                | "localeCompare"
                | "match"
                | "matchAll"
                | "normalize"
                | "padEnd"
                | "padStart"
                | "repeat"
                | "replace"
                | "replaceAll"
                | "search"
                | "slice"
                | "small"
                | "split"
                | "startsWith"
                | "strike"
                | "sub"
                | "substr"
                | "substring"
                | "sup"
                | "toLocaleLowerCase"
                | "toLocaleUpperCase"
                | "toLowerCase"
                | "toUpperCase"
                | "toWellFormed"
                | "trim"
                | "trimEnd"
                | "trimLeft"
                | "trimRight"
                | "trimStart"
        ),
        FieldValue::Number(_) => matches!(name, "toExponential" | "toFixed" | "toPrecision"),
        FieldValue::Date(_) => matches!(
            name,
            "getDate"
                | "getDay"
                | "getFullYear"
                | "getHours"
                | "getMilliseconds"
                | "getMinutes"
                | "getMonth"
                | "getSeconds"
                | "getTime"
                | "getTimezoneOffset"
                | "getUTCDate"
                | "getUTCDay"
                | "getUTCFullYear"
                | "getUTCHours"
                | "getUTCMilliseconds"
                | "getUTCMinutes"
                | "getUTCMonth"
                | "getUTCSeconds"
                | "getYear"
                | "setDate"
                | "setFullYear"
                | "setHours"
                | "setMilliseconds"
                | "setMinutes"
                | "setMonth"
                | "setSeconds"
                | "setTime"
                | "setUTCDate"
                | "setUTCFullYear"
                | "setUTCHours"
                | "setUTCMilliseconds"
                | "setUTCMinutes"
                | "setUTCMonth"
                | "setUTCSeconds"
                | "setYear"
                | "toDateString"
                | "toGMTString"
                | "toISOString"
                | "toJSON"
                | "toLocaleDateString"
                | "toLocaleTimeString"
                | "toTimeString"
                | "toUTCString"
        ),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use better_auth_core::{FieldFunction, FieldMap, user_fields::UserFieldFactory};
    use serde_json::json;
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };

    #[test]
    fn function_permissions_preserve_property_and_action_boundaries() {
        let calls = Arc::new(AtomicUsize::new(0));
        let observed = calls.clone();
        let factory: UserFieldFactory = Arc::new(move || {
            let _ = observed.fetch_add(1, Ordering::SeqCst);
            Ok(FieldValue::Undefined)
        });
        let function = FieldValue::from(FieldFunction::from(factory));
        assert!(matches!(
            check_permissions(&function, &FieldValue::from(json!({"name":["read"]}))),
            Err(AuthError::Internal(message))
                if message == "JavaScript function properties are unavailable for this Rust field callback"
        ));
        let permissions = FieldValue::from(FieldMap::from([("documents".into(), function)]));
        assert!(matches!(
            check_permissions(&permissions, &FieldValue::from(json!({"documents":["read"]}))),
            Err(AuthError::Internal(message))
                if message == "allowedActions.includes is not a function"
        ));
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    }
}
