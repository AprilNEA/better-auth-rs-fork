use super::FieldValue;
use crate::{AuthError, AuthResult};

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum PrimitiveHint {
    String,
    Number,
    Default,
}

impl FieldValue {
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
