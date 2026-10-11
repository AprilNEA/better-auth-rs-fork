//! Adapter values retain JavaScript numbers and object or function identity until an explicit boundary.

use crate::{AuthError, AuthResult};
use chrono::{DateTime, Datelike, Utc};
use indexmap::IndexMap;
use serde_json::Value as JsonValue;
use std::{
    collections::HashSet,
    ops::{Deref, DerefMut},
    sync::Arc,
};

mod array;
pub(crate) use array::{ArrayIdentity, FieldArraySource};
pub use array::{FieldArray, FieldArrayIter};
mod function;
pub use function::FieldFunction;
mod object;
pub(crate) use object::ObjectIdentity;
pub use object::{FieldObject, FieldObjectSource, FieldPropertyDescriptor};
mod structured_clone;
#[doc(hidden)]
pub use structured_clone::ObjectCloneSeed;
pub use structured_clone::StructuredCloneContext;
pub(crate) use structured_clone::{ArrayCloneSeed, prepare_clone};
mod json;
pub(crate) use json::{project_input_json, stringify_http};
mod primitive;
pub(crate) use primitive::PrimitiveHint;
pub mod serde;

/// An immutable Date object. Clones retain identity, including for an invalid Date.
/// `PartialEq` compares stored milliseconds; use `same_object` for object identity.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FieldDate(Arc<Option<i64>>);

impl FieldDate {
    /// Apply ECMAScript TimeClip while retaining valid milliseconds beyond Chrono's range.
    pub fn from_milliseconds(milliseconds: f64) -> Self {
        let clipped = (milliseconds.is_finite() && milliseconds.abs() <= 8_640_000_000_000_000.0)
            .then(|| milliseconds.trunc() as i64);
        Self(Arc::new(clipped))
    }

    /// Create a distinct invalid Date object.
    pub fn invalid() -> Self {
        Self(Arc::new(None))
    }

    /// Read the Date timestamp. Invalid dates return NaN.
    pub fn milliseconds(&self) -> f64 {
        self.0.map_or(f64::NAN, |milliseconds| milliseconds as f64)
    }

    /// Convert a valid Date to Chrono. Invalid dates return `None`.
    /// Valid dates outside Chrono's range return an error instead of becoming invalid dates.
    pub fn to_datetime(&self) -> AuthResult<Option<DateTime<Utc>>> {
        self.0
            .map(|milliseconds| {
                crate::utils::date::from_milliseconds(milliseconds as f64).ok_or_else(|| {
                    AuthError::internal("Valid Date milliseconds exceed Chrono's supported range")
                })
            })
            .transpose()
    }

    fn iso_string(&self) -> AuthResult<Option<String>> {
        let Some(milliseconds) = *self.0 else {
            return Ok(None);
        };
        const YEAR_2000: i64 = 946_684_800_000;
        const CYCLE_MILLISECONDS: i64 = 146_097 * 86_400_000;
        let offset = milliseconds - YEAR_2000;
        // Gregorian dates repeat every 400 years. Euclidean division keeps negative dates in 2000..2399.
        let date = DateTime::<Utc>::from_timestamp_millis(
            YEAR_2000 + offset.rem_euclid(CYCLE_MILLISECONDS),
        )
        .ok_or_else(|| AuthError::internal("Cannot construct a Date within the Gregorian cycle"))?;
        let year = i64::from(date.year()) + 400 * offset.div_euclid(CYCLE_MILLISECONDS);
        let year = if (0..=9999).contains(&year) {
            format!("{year:04}")
        } else {
            format!("{year:+07}")
        };
        Ok(Some(format!(
            "{year}{}",
            date.format("-%m-%dT%H:%M:%S%.3fZ")
        )))
    }

    /// Compare Date object identity without comparing timestamps.
    pub fn same_object(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.0, &other.0)
    }
}

impl From<DateTime<Utc>> for FieldDate {
    fn from(value: DateTime<Utc>) -> Self {
        Self(Arc::new(Some(value.timestamp_millis())))
    }
}

/// Ordered record fields. Clones preserve the handles stored in field values.
/// An object value supplies identity through its `FieldObject` handle.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct FieldMap(IndexMap<String, FieldValue>);

impl FieldMap {
    pub fn new() -> Self {
        Self::default()
    }

    /// Remove a property without changing the order of the remaining properties.
    pub fn remove(&mut self, name: &str) -> Option<FieldValue> {
        self.0.shift_remove(name)
    }

    /// Preserve source property order, then append remaining fields.
    pub fn in_field_order(mut self, order: &[String]) -> Self {
        let mut fields = Self::new();
        for name in order {
            if let Some(value) = self.remove(name) {
                let _ = fields.insert(name.clone(), value);
            }
        }
        fields.extend(self);
        fields
    }

    /// Overlay present schema slots, preserve extension fields, and restore source order.
    /// A missing slot leaves an extension value unchanged; an explicit Undefined is present.
    pub fn with_schema_fields<'a>(
        mut self,
        order: &[String],
        fields: impl IntoIterator<Item = (&'a str, Option<FieldValue>)>,
    ) -> Self {
        for (name, value) in fields {
            if let Some(value) = value {
                let _ = self.insert(name.into(), value);
            }
        }
        self.in_field_order(order)
    }

    /// Order array-index properties first and retain insertion order for other properties.
    pub(crate) fn sort_property_order(&mut self) {
        self.0.sort_by_key(|name, _| {
            crate::utils::json::array_index(name).map_or((true, 0), |index| (false, index))
        });
    }

    /// Import object fields at a JSON boundary without reviving Date strings.
    pub fn from_json(fields: ::serde_json::Map<String, JsonValue>) -> AuthResult<Self> {
        fields
            .into_iter()
            .map(|(name, value)| Ok((name, FieldValue::from_json(value)?)))
            .collect()
    }

    /// Prepare each child field at a JSON boundary without invoking a root `toJSON` method.
    pub fn json(&self) -> AuthResult<::serde_json::Map<String, JsonValue>> {
        json::project_map(self)
    }
}

impl<const N: usize> From<[(String, FieldValue); N]> for FieldMap {
    fn from(fields: [(String, FieldValue); N]) -> Self {
        fields.into_iter().collect()
    }
}

impl Deref for FieldMap {
    type Target = IndexMap<String, FieldValue>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for FieldMap {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl FromIterator<(String, FieldValue)> for FieldMap {
    fn from_iter<T: IntoIterator<Item = (String, FieldValue)>>(iter: T) -> Self {
        Self(iter.into_iter().collect())
    }
}

impl IntoIterator for FieldMap {
    type Item = (String, FieldValue);
    type IntoIter = indexmap::map::IntoIter<String, FieldValue>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

impl<'a> IntoIterator for &'a FieldMap {
    type Item = (&'a String, &'a FieldValue);
    type IntoIter = indexmap::map::Iter<'a, String, FieldValue>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.iter()
    }
}

impl<'a> IntoIterator for &'a mut FieldMap {
    type Item = (&'a String, &'a mut FieldValue);
    type IntoIter = indexmap::map::IterMut<'a, String, FieldValue>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.iter_mut()
    }
}

/// A field value before adapter conversion or JSON serialization.
/// `PartialEq` compares owned objects structurally and live objects by source identity.
/// Use `strict_equals` or `same_value_zero` for JavaScript comparisons.
/// Memory row merge detection compares `stringify` results; credential guards preserve native value distinctions.
#[derive(Clone, Debug, Default, PartialEq)]
pub enum FieldValue {
    #[default]
    Undefined,
    Null,
    Bool(bool),
    Number(f64),
    String(String),
    Utf16String(crate::Utf16String),
    Date(FieldDate),
    Array(FieldArray),
    Object(FieldObject),
    Function(FieldFunction),
}

impl FieldValue {
    /// Decode the requested Rust type without serializing the field value.
    pub fn decode<T: crate::SchemaField>(&self) -> AuthResult<T> {
        T::from_field(self.clone())
            .map_err(|_| AuthError::internal("Adapter field does not have the requested Rust type"))
    }

    /// Move this value out and leave undefined in its place.
    pub fn take(&mut self) -> Self {
        std::mem::take(self)
    }

    pub fn is_string(&self) -> bool {
        matches!(self, Self::String(_) | Self::Utf16String(_))
    }

    pub fn is_number(&self) -> bool {
        matches!(self, Self::Number(_))
    }

    pub fn is_array(&self) -> bool {
        matches!(self, Self::Array(_))
    }

    pub fn is_object(&self) -> bool {
        matches!(self, Self::Object(_))
    }

    pub fn is_undefined(&self) -> bool {
        matches!(self, Self::Undefined)
    }

    /// Test for raw undefined or function values without invoking conversion hooks.
    pub fn is_json_omitted(&self) -> bool {
        matches!(self, Self::Undefined | Self::Function(_))
    }

    pub fn is_null(&self) -> bool {
        matches!(self, Self::Null)
    }

    pub fn as_bool(&self) -> Option<bool> {
        match self {
            Self::Bool(value) => Some(*value),
            _ => None,
        }
    }

    pub fn as_f64(&self) -> Option<f64> {
        match self {
            Self::Number(value) => Some(*value),
            _ => None,
        }
    }

    pub fn as_str(&self) -> Option<&str> {
        match self {
            Self::String(value) => Some(value),
            _ => None,
        }
    }

    pub fn as_date(&self) -> Option<&FieldDate> {
        match self {
            Self::Date(value) => Some(value),
            _ => None,
        }
    }

    pub fn as_array(&self) -> Option<&FieldArray> {
        match self {
            Self::Array(value) => Some(value),
            _ => None,
        }
    }

    pub fn as_object(&self) -> Option<&FieldObject> {
        match self {
            Self::Object(value) => Some(value),
            _ => None,
        }
    }

    /// Read a named model field without narrowing its value or a non-null receiver.
    /// Null and undefined reject property access; other non-record values have no model fields.
    pub fn model_property(&self, name: &str) -> AuthResult<Self> {
        let nullish = match self {
            Self::Null => Some("null"),
            Self::Undefined => Some("undefined"),
            _ => None,
        };
        if let Some(nullish) = nullish {
            return Err(AuthError::type_error(format!(
                "Cannot read properties of {nullish} (reading '{name}')"
            )));
        }
        match self.as_object() {
            Some(fields) => Ok(fields.get(name)?.unwrap_or_default()),
            None => Ok(Self::Undefined),
        }
    }

    /// Copy own enumerable properties while retaining native child identities.
    /// String keys enumerate UTF-16 units, as in object spread and `Object.entries`.
    pub fn enumerable_fields(&self) -> AuthResult<FieldMap> {
        Ok(match self {
            Self::Object(_) => return self.enumerable_fields_except(&[]),
            Self::Array(values) => {
                let mut fields = FieldMap::new();
                for index in values.own_indices()? {
                    if let Some(value) = values.get(index)? {
                        let _ = fields.insert(index.to_string(), value);
                    }
                }
                fields
            }
            Self::String(value) => string_fields(value.encode_utf16()),
            Self::Utf16String(value) => string_fields(value.as_utf16().iter().copied()),
            _ => FieldMap::new(),
        })
    }

    /// Copy object-rest properties without reading an excluded property's getter.
    pub fn enumerable_fields_except(&self, excluded: &[&str]) -> AuthResult<FieldMap> {
        match self {
            Self::Object(object) => {
                let mut fields = FieldMap::new();
                for name in object.own_keys()? {
                    if !excluded.contains(&name.as_str())
                        && object
                            .own_property_descriptor(&name)?
                            .is_some_and(|descriptor| descriptor.enumerable)
                    {
                        let value = object.get(&name)?.unwrap_or_default();
                        let _ = fields.insert(name, value);
                    }
                }
                Ok(fields)
            }
            Self::Array(array) => {
                let mut fields = FieldMap::new();
                for index in array.own_indices()? {
                    let name = index.to_string();
                    if !excluded.contains(&name.as_str())
                        && let Some(value) = array.get(index)?
                    {
                        let _ = fields.insert(name, value);
                    }
                }
                Ok(fields)
            }
            _ => {
                let mut fields = self.enumerable_fields()?;
                fields.retain(|name, _| !excluded.contains(&name.as_str()));
                Ok(fields)
            }
        }
    }

    /// Evaluate JavaScript truthiness without serializing numbers or objects.
    pub fn is_truthy(&self) -> bool {
        match self {
            Self::Undefined | Self::Null => false,
            Self::Bool(value) => *value,
            Self::Number(value) => *value != 0.0 && !value.is_nan(),
            Self::String(value) => !value.is_empty(),
            Self::Utf16String(value) => !value.as_utf16().is_empty(),
            Self::Date(_) | Self::Array(_) | Self::Object(_) | Self::Function(_) => true,
        }
    }

    /// Apply JavaScript strict equality, including object identity and NaN inequality.
    pub fn strict_equals(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Undefined, Self::Undefined) | (Self::Null, Self::Null) => true,
            (Self::Bool(left), Self::Bool(right)) => left == right,
            (Self::Number(left), Self::Number(right)) => left == right,
            (Self::String(left), Self::String(right)) => left == right,
            (Self::Utf16String(left), Self::Utf16String(right)) => left == right,
            (Self::String(left), Self::Utf16String(right))
            | (Self::Utf16String(right), Self::String(left)) => {
                left.encode_utf16().eq(right.as_utf16().iter().copied())
            }
            (Self::Date(left), Self::Date(right)) => left.same_object(right),
            (Self::Array(left), Self::Array(right)) => left.same_array(right),
            (Self::Object(left), Self::Object(right)) => left.same_object(right),
            (Self::Function(left), Self::Function(right)) => left == right,
            _ => false,
        }
    }

    /// Apply the SameValueZero comparison used by JavaScript array `includes`.
    pub fn same_value_zero(&self, other: &Self) -> bool {
        matches!((self, other), (Self::Number(left), Self::Number(right)) if left.is_nan() && right.is_nan())
            || self.strict_equals(other)
    }

    /// Import JSON values without reviving strings as Date objects.
    pub fn from_json(value: JsonValue) -> AuthResult<Self> {
        Ok(value.into())
    }

    /// Prepare each property once, including its `toJSON` method, then project JSON values.
    /// Prepared undefined and functions are absent at the root, omitted in objects, and null in arrays.
    pub fn json(&self) -> AuthResult<Option<JsonValue>> {
        json::to_value(self)
    }

    /// Parse JSON without discarding lone UTF-16 surrogates or nested field ordering.
    pub fn parse_json(text: &str) -> AuthResult<Self> {
        crate::utils::json::parse_field_json(text)
    }

    /// Serialize with JavaScript property ordering, numeric formatting, and `toJSON` conversion.
    pub fn stringify(&self) -> AuthResult<Option<String>> {
        json::stringify(self)
    }
}

fn string_fields(units: impl Iterator<Item = u16>) -> FieldMap {
    units
        .enumerate()
        .map(|(index, unit)| {
            (
                index.to_string(),
                crate::Utf16String::from_units(vec![unit]).into(),
            )
        })
        .collect()
}

impl From<bool> for FieldValue {
    fn from(value: bool) -> Self {
        Self::Bool(value)
    }
}

impl From<f64> for FieldValue {
    fn from(value: f64) -> Self {
        Self::Number(value)
    }
}

impl From<String> for FieldValue {
    fn from(value: String) -> Self {
        Self::String(value)
    }
}

impl From<&str> for FieldValue {
    fn from(value: &str) -> Self {
        Self::String(value.to_owned())
    }
}

impl From<crate::Utf16String> for FieldValue {
    fn from(value: crate::Utf16String) -> Self {
        match value.to_utf8() {
            Ok(value) => Self::String(value),
            Err(_) => Self::Utf16String(value),
        }
    }
}

impl From<FieldDate> for FieldValue {
    fn from(value: FieldDate) -> Self {
        Self::Date(value)
    }
}

impl From<DateTime<Utc>> for FieldValue {
    fn from(value: DateTime<Utc>) -> Self {
        Self::Date(value.into())
    }
}

impl From<Vec<FieldValue>> for FieldValue {
    fn from(value: Vec<FieldValue>) -> Self {
        Self::Array(value.into())
    }
}

impl From<FieldArray> for FieldValue {
    fn from(value: FieldArray) -> Self {
        Self::Array(value)
    }
}

impl From<FieldMap> for FieldValue {
    fn from(value: FieldMap) -> Self {
        Self::Object(value.into())
    }
}

#[cfg(test)]
mod object_tests;
#[cfg(test)]
mod tests;

impl FieldValue {
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
            Self::Function(_) => {
                // ponytail: Rust callbacks have no JavaScript source text; explicit reflection is required for function coercion.
                return Err(AuthError::internal(
                    "JavaScript function source is unavailable for this Rust field callback",
                ));
            }
            Self::Object(_) => self
                .primitive(PrimitiveHint::String)?
                .display_utf16_with_active(active)?,
            Self::Date(value) => match value.to_datetime()? {
                Some(value) => value
                    .with_timezone(&chrono::Local)
                    .format("%a %b %d %Y %H:%M:%S GMT%z (%Z)")
                    .to_string()
                    .into(),
                None => "Invalid Date".into(),
            },
            Self::Array(values) => {
                let identity = values.identity();
                if !active.insert(identity) {
                    return Ok("".into());
                }
                let mut units = Vec::new();
                for (index, value) in values.iter()?.enumerate() {
                    let value = value?;
                    if index != 0 {
                        units.push(u16::from(b','));
                    }
                    if !value.is_undefined() && !value.is_null() {
                        units
                            .extend_from_slice(value.display_utf16_with_active(active)?.as_utf16());
                    }
                }
                let _ = active.remove(&identity);
                crate::Utf16String::from_units(units)
            }
        })
    }
}

impl From<JsonValue> for FieldValue {
    fn from(value: JsonValue) -> Self {
        match value {
            JsonValue::Null => Self::Null,
            JsonValue::Bool(value) => Self::Bool(value),
            JsonValue::Number(value) => Self::Number(json_number(&value)),
            JsonValue::String(value) => Self::String(value),
            JsonValue::Array(values) => values
                .into_iter()
                .map(Self::from)
                .collect::<Vec<_>>()
                .into(),
            JsonValue::Object(values) => values
                .into_iter()
                .map(|(name, value)| (name, Self::from(value)))
                .collect::<FieldMap>()
                .into(),
        }
    }
}

fn json_number(value: &serde_json::Number) -> f64 {
    value.as_f64().unwrap_or_else(|| {
        // Arbitrary-precision JSON numbers can exceed f64. JavaScript JSON.parse retains signed infinity.
        if value.to_string().starts_with('-') {
            f64::NEG_INFINITY
        } else {
            f64::INFINITY
        }
    })
}

#[derive(Clone, Copy, Hash, PartialEq, Eq)]
pub(crate) enum ContainerIdentity {
    Array(ArrayIdentity),
    Object(ObjectIdentity),
}
