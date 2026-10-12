use super::*;
pub(super) use better_auth_core::utils::json::parse_native_json as parse_json;
use better_auth_core::{FieldMap, FieldValue};

pub(super) fn algorithm(key: &better_auth_core::Jwk, fallback: FieldValue) -> FieldValue {
    let value = key.alg.field_value();
    if value.is_null() || value.is_undefined() {
        fallback
    } else {
        value
    }
}

pub(super) fn expires_before(key: &better_auth_core::Jwk, now: i64) -> AuthResult<bool> {
    let expiry = key.expires_at.field_value();
    Ok(expiry.is_truthy()
        && better_auth_core::query::field_compare(&expiry, &(now as f64).into())?
            == Some(std::cmp::Ordering::Less))
}

pub(super) fn latest(
    keys: Vec<better_auth_core::Jwk>,
    algorithm: Option<&str>,
    default_algorithm: &str,
) -> AuthResult<Option<better_auth_core::Jwk>> {
    let now = FieldValue::from(Utc::now().timestamp_millis() as f64);
    let mut candidates = Vec::new();
    for key in keys {
        if let Some(expected) = algorithm {
            let alg = key.alg.field_value();
            if !alg.strict_equals(&expected.into())
                && !((alg.is_null() || alg.is_undefined()) && default_algorithm == expected)
            {
                continue;
            }
        }
        let expiry = key.expires_at.field_value();
        if !expiry.is_truthy()
            || better_auth_core::query::field_compare(&expiry, &now)?
                == Some(std::cmp::Ordering::Greater)
        {
            candidates.push(key);
        }
    }
    better_auth_core::query::sort_by(&mut candidates, |left, right| {
        let right = right
            .created_at
            .field_value()
            .get_time_method("b.createdAt")?;
        let left = left
            .created_at
            .field_value()
            .get_time_method("a.createdAt")?;
        Ok((better_auth_core::query::field_number(&right)?
            - better_auth_core::query::field_number(&left)?)
        .partial_cmp(&0.0)
        .unwrap_or(std::cmp::Ordering::Equal))
    })?;
    Ok(candidates.into_iter().next())
}

pub(super) fn spread(fields: &mut FieldMap, value: FieldValue) -> AuthResult<()> {
    fields.extend(value.enumerable_fields()?);
    Ok(())
}

pub(super) fn import(value: FieldValue, alg: &FieldValue) -> AuthResult<(String, Jwk)> {
    let fields = value
        .as_object()
        .ok_or_else(|| AuthError::internal("JWK must be an object"))?
        .snapshot_fields()?;
    if fields
        .get("ext")
        .is_some_and(|value| !value.is_undefined() && !matches!(value, FieldValue::Bool(_)))
    {
        return Err(AuthError::internal(
            "\"ext\" (Extractable) Parameter must be a boolean",
        ));
    }
    if let Some(operations) = fields.get("key_ops").filter(|value| !value.is_undefined()) {
        let invalid_operations = || {
            AuthError::internal(
                "\"key_ops\" (Key Operations) Parameter must be an array of unique strings",
            )
        };
        let operations = operations.as_array().ok_or_else(invalid_operations)?;
        let mut seen = std::collections::HashSet::new();
        for value in operations.iter()? {
            let value = value?;
            let name = value.as_str().ok_or_else(invalid_operations)?;
            if !seen.insert(name.to_owned()) {
                return Err(invalid_operations());
            }
        }
    }
    let kind = fields.get("kty").and_then(FieldValue::as_str);
    if kind != Some("oct") && !alg.is_truthy() {
        return Err(AuthError::internal(
            "\"alg\" argument is required when \"jwk.alg\" is not present",
        ));
    }
    if !matches!(kind, Some("RSA" | "EC" | "OKP" | "oct")) {
        return Err(AuthError::internal(
            "Unsupported \"kty\" (Key Type) Parameter value",
        ));
    }
    let algorithm = alg
        .as_str()
        .filter(|value| matches!(*value, "EdDSA" | "RS256" | "ES256" | "ES512" | "PS256"))
        .ok_or_else(|| {
            AuthError::internal("Invalid or unsupported JWK \"alg\" (Algorithm) Parameter value")
        })?;
    if algorithm == "EdDSA" && fields.get("crv").and_then(FieldValue::as_str) != Some("Ed25519") {
        return Err(AuthError::internal(
            "JWK \"crv\" (Curve) does not match the Ed25519 algorithm",
        ));
    }
    let mut fields = fields.clone();
    // WebCrypto consumes key material and key_ops; metadata does not constrain the imported key.
    for name in ["alg", "use", "kid"] {
        let _ = fields.remove(name);
    }
    let encoded = FieldValue::from(fields)
        .stringify()?
        .ok_or_else(|| AuthError::internal("JWK must be an object"))?;
    Ok((
        algorithm.to_owned(),
        Jwk::from_bytes(encoded).map_err(jose_error)?,
    ))
}
