use super::{ArrayIdentity, FieldArray, FieldValue};
use crate::{AuthError, AuthResult};
use std::collections::HashSet;

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum PrimitiveHint {
    String,
    Number,
    Default,
}

enum PrimitiveValue {
    Value(FieldValue),
    FunctionSource,
}

impl PrimitiveValue {
    fn into_value(self) -> AuthResult<FieldValue> {
        match self {
            Self::Value(value) => Ok(value),
            Self::FunctionSource => Err(AuthError::internal(
                "JavaScript function source is unavailable for this Rust field callback",
            )),
        }
    }
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

    /// Invoke `join(separator)` without converting a custom method's native result.
    pub fn join_method(&self, separator: &Self, expression: &str) -> AuthResult<Self> {
        if self.is_null() || self.is_undefined() {
            return self.model_property("join");
        }
        let method = self
            .property_source()
            .map(|source| source.get_with_receiver("join", self))
            .transpose()?
            .flatten();
        match (self, method) {
            (_, Some(Self::Function(method))) => {
                method.call_with(self, std::slice::from_ref(separator))
            }
            (Self::Array(values), None) => {
                Ok(Self::array_join(values, separator, &mut HashSet::new())?.into())
            }
            _ => Err(AuthError::type_error(format!(
                "{expression}.join is not a function"
            ))),
        }
    }

    /// Call the receiver's `toString` method without applying ToPrimitive fallback.
    pub(crate) fn call_to_string(&self) -> AuthResult<Self> {
        if let Some(fields) = self.property_source() {
            return match fields.get_with_receiver("toString", self)? {
                Some(Self::Function(method)) => method.call_with(self, &[]),
                None => self.builtin_to_string(&mut HashSet::new())?.into_value(),
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
        self.primitive_with_active(hint, &mut HashSet::new())?
            .into_value()
    }

    pub(crate) fn number_primitive(&self) -> AuthResult<Self> {
        match self.primitive_with_active(PrimitiveHint::Number, &mut HashSet::new())? {
            PrimitiveValue::Value(value) => Ok(value),
            // Function source cannot form a numeric literal. Other consumers require the source text.
            PrimitiveValue::FunctionSource => Ok(Self::Number(f64::NAN)),
        }
    }

    fn primitive_with_active(
        &self,
        hint: PrimitiveHint,
        active: &mut HashSet<ArrayIdentity>,
    ) -> AuthResult<PrimitiveValue> {
        let Some(fields) = self.property_source() else {
            return Ok(PrimitiveValue::Value(self.clone()));
        };
        let methods = if hint == PrimitiveHint::String
            || (hint == PrimitiveHint::Default && matches!(self, Self::Date(_)))
        {
            ["toString", "valueOf"]
        } else {
            ["valueOf", "toString"]
        };
        for name in methods {
            // Read the next method only after the previous call and its side effects finish.
            let result = match fields.get_with_receiver(name, self)? {
                Some(Self::Function(function)) => {
                    PrimitiveValue::Value(function.call_with(self, &[])?)
                }
                None if name == "toString" => self.builtin_to_string(active)?,
                None => PrimitiveValue::Value(match self {
                    Self::Date(date) => Self::Number(date.milliseconds()),
                    value => value.clone(),
                }),
                Some(_) => continue,
            };
            if !matches!(
                &result,
                PrimitiveValue::Value(
                    Self::Object(_) | Self::Array(_) | Self::Date(_) | Self::Function(_)
                )
            ) {
                return Ok(result);
            }
        }
        Err(AuthError::type_error("No default value"))
    }

    fn builtin_to_string(&self, active: &mut HashSet<ArrayIdentity>) -> AuthResult<PrimitiveValue> {
        Ok(PrimitiveValue::Value(match self {
            Self::Function(_) => return Ok(PrimitiveValue::FunctionSource),
            Self::Date(date) => match date.to_datetime()? {
                Some(value) => value
                    .with_timezone(&chrono::Local)
                    .format("%a %b %d %Y %H:%M:%S GMT%z (%Z)")
                    .to_string()
                    .into(),
                None => "Invalid Date".into(),
            },
            Self::Array(values) => match values.properties().get_with_receiver("join", self)? {
                Some(Self::Function(join)) => join.call_with(self, &[])?,
                Some(_) => "[object Array]".into(),
                None => Self::array_join(values, &Self::Undefined, active)?.into(),
            },
            _ => "[object Object]".into(),
        }))
    }

    /// Apply JavaScript string conversion while retaining unpaired UTF-16 code units.
    pub fn display_utf16(&self) -> AuthResult<crate::Utf16String> {
        self.display_utf16_with_active(&mut HashSet::new())
    }

    fn display_utf16_with_active(
        &self,
        active: &mut HashSet<ArrayIdentity>,
    ) -> AuthResult<crate::Utf16String> {
        Ok(match self {
            Self::Undefined => "undefined".into(),
            Self::Null => "null".into(),
            Self::String(value) => value.as_str().into(),
            Self::Utf16String(value) => value.clone(),
            Self::Bool(value) => value.to_string().into(),
            Self::Number(value) => crate::schema_value::number_string(*value).into(),
            Self::Object(_) | Self::Array(_) | Self::Date(_) | Self::Function(_) => self
                .primitive_with_active(PrimitiveHint::String, active)?
                .into_value()?
                .display_utf16_with_active(active)?,
        })
    }

    fn array_join(
        values: &FieldArray,
        separator: &Self,
        active: &mut HashSet<ArrayIdentity>,
    ) -> AuthResult<crate::Utf16String> {
        let iterator = values.iter()?;
        let separator = if separator.is_undefined() {
            ",".into()
        } else {
            separator.display_utf16_with_active(active)?
        };
        let identity = values.identity();
        if !active.insert(identity) {
            return Ok("".into());
        }
        let result = (|| {
            let mut units = Vec::new();
            for (index, value) in iterator.enumerate() {
                let value = value?;
                if index != 0 {
                    units.extend_from_slice(separator.as_utf16());
                }
                if !value.is_undefined() && !value.is_null() {
                    units.extend_from_slice(value.display_utf16_with_active(active)?.as_utf16());
                }
            }
            Ok(crate::Utf16String::from_units(units))
        })();
        let _ = active.remove(&identity);
        result
    }
}

#[cfg(test)]
#[path = "primitive_tests.rs"]
mod tests;
