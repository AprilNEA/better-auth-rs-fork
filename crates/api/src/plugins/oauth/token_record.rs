//! Shared token-record projection preserves native slots, source order, and object identity.

use better_auth_core::{
    AuthError, AuthResult, FieldMap, FieldValue, SchemaField, SchemaValue, Utf16String,
};

use super::{OAuthCallbackUserName, OAuthCallbackUserPayload, OAuthTokenSet, OAuthUserInfoRequest};

fn take<T: SchemaField>(fields: &mut FieldMap, name: &str) -> SchemaValue<T> {
    match fields.remove(name) {
        None => SchemaValue::Undefined,
        Some(FieldValue::Undefined) => SchemaValue::Dynamic(FieldValue::Undefined),
        Some(value) => SchemaValue::from_field(value),
    }
}

fn slot<T: SchemaField>(value: &SchemaValue<T>) -> Option<FieldValue> {
    (!value.is_undefined()).then(|| value.field_value())
}

macro_rules! token_record {
    ($record:ty $(, $name:ident => $key:literal)*) => {
        impl $record {
            /// Decode each named slot without discarding replacement values or object handles.
            pub fn from_fields(mut fields: FieldMap) -> Self {
                Self {
                    field_order: fields.keys().cloned().collect(),
                    token_type: take(&mut fields, "tokenType"),
                    access_token: take(&mut fields, "accessToken"),
                    refresh_token: take(&mut fields, "refreshToken"),
                    access_token_expires_at: take(&mut fields, "accessTokenExpiresAt"),
                    refresh_token_expires_at: take(&mut fields, "refreshTokenExpiresAt"),
                    scopes: take(&mut fields, "scopes"),
                    id_token: take(&mut fields, "idToken"),
                    raw: take(&mut fields, "raw"),
                    $($name: take(&mut fields, $key),)*
                    additional_fields: fields,
                }
            }

            /// Return the complete ordered record. Present named slots override extension fields.
            pub fn fields(&self) -> FieldMap {
                self.additional_fields.clone().with_schema_fields(&self.field_order, [
                    ("tokenType", slot(&self.token_type)),
                    ("accessToken", slot(&self.access_token)),
                    ("refreshToken", slot(&self.refresh_token)),
                    ("accessTokenExpiresAt", slot(&self.access_token_expires_at)),
                    ("refreshTokenExpiresAt", slot(&self.refresh_token_expires_at)),
                    ("scopes", slot(&self.scopes)),
                    ("idToken", slot(&self.id_token)),
                    ("raw", slot(&self.raw)),
                    $(($key, slot(&self.$name)),)*
                ])
            }
        }
    };
}

token_record!(OAuthTokenSet);
token_record!(OAuthUserInfoRequest, expected_id_token_nonce => "expectedIdTokenNonce", user => "user");

impl From<OAuthTokenSet> for OAuthUserInfoRequest {
    fn from(tokens: OAuthTokenSet) -> Self {
        Self::from_fields(tokens.fields())
    }
}

impl SchemaField for OAuthCallbackUserPayload {
    fn from_field(value: FieldValue) -> Result<Self, FieldValue> {
        let json = <serde_json::Value as SchemaField>::from_field(value.clone())?;
        serde_json::from_value(json).map_err(|_| value)
    }

    fn into_field(self) -> FieldValue {
        let mut fields = FieldMap::new();
        if let Some(name) = self.name {
            let _ = fields.insert("name".into(), name.into_field());
        }
        if let Some(email) = self.email {
            let _ = fields.insert("email".into(), email.into());
        }
        fields.into()
    }
}

impl SchemaField for OAuthCallbackUserName {
    fn from_field(value: FieldValue) -> Result<Self, FieldValue> {
        let json = <serde_json::Value as SchemaField>::from_field(value.clone())?;
        serde_json::from_value(json).map_err(|_| value)
    }

    fn into_field(self) -> FieldValue {
        let mut fields = FieldMap::new();
        if let Some(name) = self.first_name {
            let _ = fields.insert("firstName".into(), name.into());
        }
        if let Some(name) = self.last_name {
            let _ = fields.insert("lastName".into(), name.into());
        }
        fields.into()
    }
}

/// Optional chaining checks nullish values before invoking Array.join.
pub(super) fn joined_scopes(value: &SchemaValue<Vec<String>>) -> AuthResult<FieldValue> {
    match value.field_value() {
        FieldValue::Null | FieldValue::Undefined => Ok(FieldValue::Undefined),
        value @ FieldValue::Array(_) => Ok(value.display_utf16()?.into()),
        _ => Err(AuthError::type_error(
            "tokens.scopes?.join is not a function",
        )),
    }
}

fn string_units(value: &FieldValue, operation: &str) -> AuthResult<Utf16String> {
    match value {
        FieldValue::String(value) => Ok(value.as_str().into()),
        FieldValue::Utf16String(value) => Ok(value.clone()),
        _ => Err(AuthError::type_error(format!(
            "{operation} is not a function"
        ))),
    }
}

fn trimmed(units: &[u16]) -> Utf16String {
    let whitespace = |unit: &u16| {
        char::from_u32(u32::from(*unit))
            .is_some_and(crate::plugins::helpers::oauth_scope_whitespace)
    };
    let start = units
        .iter()
        .position(|unit| !whitespace(unit))
        .unwrap_or(units.len());
    let end = units
        .iter()
        .rposition(|unit| !whitespace(unit))
        .map_or(start, |index| index + 1);
    Utf16String::from_units(units.get(start..end).unwrap_or_default().to_vec())
}

pub(super) fn split_scopes(value: &FieldValue) -> AuthResult<Vec<FieldValue>> {
    if !value.is_truthy() {
        return Ok(Vec::new());
    }
    Ok(string_units(value, "scope.split")?
        .as_utf16()
        .split(|unit| *unit == u16::from(b','))
        .map(trimmed)
        .filter(|scope| !scope.as_utf16().is_empty())
        .map(Into::into)
        .collect())
}

pub(super) fn merge_scopes(
    stored: &FieldValue,
    incoming: &SchemaValue<Vec<String>>,
) -> AuthResult<FieldValue> {
    let mut values = split_scopes(stored)?;
    match incoming.field_value() {
        FieldValue::Null | FieldValue::Undefined => {}
        FieldValue::Array(array) => {
            for index in 0..array.len()? {
                if let Some(value) = array.get(index)? {
                    let value = trimmed(string_units(&value, "scope.trim")?.as_utf16());
                    if !value.as_utf16().is_empty() {
                        values.push(value.into());
                    }
                }
            }
        }
        _ => {
            return Err(AuthError::type_error(
                "(incoming ?? []).map is not a function",
            ));
        }
    }
    let mut unique: Vec<Utf16String> = Vec::new();
    for value in values {
        let value = string_units(&value, "scope.trim")?;
        if !unique.contains(&value) {
            unique.push(value);
        }
    }
    let values: Vec<FieldValue> = unique.into_iter().map(Into::into).collect();
    Ok(FieldValue::from(values).display_utf16()?.into())
}

#[cfg(test)]
#[path = "token_record_tests.rs"]
mod tests;
