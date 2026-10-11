use super::FieldValue;
use crate::{AuthError, AuthResult};

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum PrimitiveHint {
    String,
    Number,
    Default,
}

impl FieldValue {
    /// Invoke `toLowerCase` at a business read, retaining a custom method's native result.
    pub fn lowercase_method(&self, expression: &str) -> AuthResult<Self> {
        match self {
            Self::String(text) => Ok(crate::Utf16String::from(text.as_str())
                .to_lowercase()
                .into()),
            Self::Utf16String(text) => Ok(text.to_lowercase().into()),
            Self::Null | Self::Undefined => {
                let kind = if self.is_null() { "null" } else { "undefined" };
                Err(AuthError::type_error(format!(
                    "{kind} is not an object (evaluating '{expression}.toLowerCase')"
                )))
            }
            _ => match self.model_property("toLowerCase")? {
                Self::Function(method) => method.call_with(self, &[]),
                _ => Err(AuthError::type_error(format!(
                    "{expression}.toLowerCase is not a function. (In '{expression}.toLowerCase()', '{expression}.toLowerCase' is undefined)"
                ))),
            },
        }
    }

    /// Call the receiver's `toString` method without applying ToPrimitive fallback.
    pub(crate) fn call_to_string(&self) -> AuthResult<Self> {
        if let Self::Object(fields) = self {
            return match fields.get("toString")? {
                Some(Self::Function(method)) => method.call_with(self, &[]),
                None => Ok("[object Object]".into()),
                Some(_) => Err(AuthError::type_error(
                    "data.status.toString is not a function",
                )),
            };
        }
        if self.is_null() || self.is_undefined() {
            return self.model_property("toString");
        }
        Ok(self.display_utf16()?.into())
    }

    pub(crate) fn primitive(&self, hint: PrimitiveHint) -> AuthResult<Self> {
        let Self::Object(fields) = self else {
            return match self {
                Self::Date(date) if hint == PrimitiveHint::Number => {
                    Ok(Self::Number(date.milliseconds()))
                }
                Self::Date(_) | Self::Array(_) | Self::Function(_) => {
                    Ok(self.display_utf16()?.into())
                }
                value => Ok(value.clone()),
            };
        };
        let methods = if hint == PrimitiveHint::String {
            ["toString", "valueOf"]
        } else {
            ["valueOf", "toString"]
        };
        for name in methods {
            // Read the next method only after the previous call and its side effects finish.
            let result = match fields.get(name)? {
                Some(Self::Function(function)) => function.call_with(self, &[])?,
                None if name == "toString" => "[object Object]".into(),
                None | Some(_) => continue,
            };
            if !matches!(
                result,
                Self::Object(_) | Self::Array(_) | Self::Date(_) | Self::Function(_)
            ) {
                return Ok(result);
            }
        }
        Err(AuthError::type_error("No default value"))
    }
}

#[cfg(test)]
#[path = "primitive_tests.rs"]
mod tests;
