use super::*;
use better_auth_core::utils::jwt::numeric_date;

pub(super) fn default_expiration(
    expiration: &JwtExpiration,
    issued: Option<&FieldValue>,
) -> AuthResult<FieldValue> {
    let seconds = FieldValue::from_json(expiration.claim(0.0))?;
    if matches!(expiration, JwtExpiration::At(_)) {
        return Ok(seconds);
    }
    let issued = issued
        .filter(|value| !value.is_null() && !value.is_undefined())
        .cloned()
        .unwrap_or_else(|| Utc::now().timestamp().into());
    better_auth_core::query::field_add(&issued, &seconds)
}

pub(super) fn prepare_local_claims(
    payload: &mut FieldMap,
    original: &FieldMap,
    defaults: &FieldMap,
) -> AuthResult<()> {
    let claim = |name: &str| defaults.get(name).unwrap_or(&FieldValue::Undefined);
    let expiry = numeric_date(claim("exp"), "setExpirationTime")?;
    let _ = payload.insert("exp".into(), expiry);
    let issuer = claim("iss");
    require_string("iss", issuer)?;
    let _ = payload.insert("iss".into(), issuer.clone());
    let audience = claim("aud");
    let valid_audience = match audience {
        FieldValue::String(_) | FieldValue::Utf16String(_) => true,
        FieldValue::Array(values) => values.snapshot()?.iter().all(is_string),
        _ => false,
    };
    if !valid_audience {
        return Err(AuthError::type_error(
            "\"aud\" claim must be a string or an array of strings",
        ));
    }
    let _ = payload.insert("aud".into(), audience.clone());
    for name in ["iat", "sub", "nbf", "jti"] {
        if let Some(value) = original.get(name).filter(|value| value.is_truthy()) {
            let value = match name {
                "iat" => numeric_date(value, "setIssuedAt")?,
                "nbf" => numeric_date(value, "setNotBefore")?,
                _ => {
                    require_string(name, value)?;
                    value.clone()
                }
            };
            let _ = payload.insert(name.into(), value);
        }
    }
    Ok(())
}

fn is_string(value: &FieldValue) -> bool {
    matches!(value, FieldValue::String(_) | FieldValue::Utf16String(_))
}

pub(super) fn require_string(name: &str, value: &FieldValue) -> AuthResult<()> {
    if is_string(value) {
        Ok(())
    } else {
        Err(AuthError::type_error(format!(
            "\"{name}\" claim must be a string"
        )))
    }
}
