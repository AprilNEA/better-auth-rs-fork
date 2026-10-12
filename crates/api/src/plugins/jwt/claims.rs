use super::*;
use better_auth_core::utils::jwt::numeric_date;

pub(super) fn default_expiration(
    expiration: &JwtExpiration,
    issued: &FieldValue,
    now: i64,
) -> AuthResult<FieldValue> {
    let seconds = FieldValue::from_json(expiration.claim(0.0))?;
    if matches!(expiration, JwtExpiration::At(_)) {
        return Ok(seconds);
    }
    let issued = if issued.is_null() || issued.is_undefined() {
        now.into()
    } else {
        issued.clone()
    };
    better_auth_core::query::field_add(&issued, &seconds)
}

pub(super) fn prepare_local_claims(
    payload: &mut FieldMap,
    original: &FieldValue,
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
    let issued = claim("iat");
    if issued.is_truthy() {
        let _ = payload.insert("iat".into(), numeric_date(issued, "setIssuedAt")?);
    }
    for name in ["sub", "nbf", "jti"] {
        if original.model_property(name)?.is_truthy() {
            let value = original.model_property(name)?;
            let value = if name == "nbf" {
                numeric_date(&value, "setNotBefore")?
            } else {
                require_string(name, &value)?;
                value
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
