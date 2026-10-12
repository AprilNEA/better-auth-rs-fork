use super::*;
pub(super) use better_auth_core::utils::json::parse_native_json as parse_json;
use better_auth_core::{FieldFunction, FieldMap, FieldValue};

pub(super) fn algorithm(key: &FieldValue, fallback: FieldValue) -> AuthResult<FieldValue> {
    let value = key.model_property("alg")?;
    Ok(if value.is_null() || value.is_undefined() {
        fallback
    } else {
        value
    })
}

pub(super) fn expires_before(key: &FieldValue) -> AuthResult<bool> {
    if !key.model_property("expiresAt")?.is_truthy() {
        return Ok(false);
    }
    let expiry = key.model_property("expiresAt")?;
    let now = Utc::now().timestamp_millis() as f64;
    Ok(
        better_auth_core::query::field_compare(&expiry, &now.into())?
            == Some(std::cmp::Ordering::Less),
    )
}

pub(super) fn find(keys: &FieldValue, id: FieldValue) -> AuthResult<FieldValue> {
    keys.find_method(
        &FieldFunction::contextual(move |_, arguments| {
            Ok(arguments
                .first()
                .unwrap_or(&FieldValue::Undefined)
                .model_property("id")?
                .strict_equals(&id)
                .into())
        }),
        "keys",
    )
}

pub(super) fn latest(
    keys: FieldValue,
    algorithm: Option<FieldValue>,
    default_algorithm: FieldValue,
    now: FieldValue,
) -> AuthResult<FieldValue> {
    if if algorithm.is_some() {
        !keys.is_truthy()
    } else {
        keys.is_null() || keys.is_undefined()
    } {
        return Ok(FieldValue::Undefined);
    }
    let candidates = if let Some(expected) = algorithm {
        keys.filter_method(
            &FieldFunction::contextual(move |_, arguments| {
                let key = arguments.first().unwrap_or(&FieldValue::Undefined);
                if key.model_property("alg")?.strict_equals(&expected) {
                    return Ok(true.into());
                }
                let alg = key.model_property("alg")?;
                Ok(((alg.is_null() || alg.is_undefined())
                    && default_algorithm.strict_equals(&expected))
                .into())
            }),
            "candidates",
        )?
    } else {
        keys
    };
    let live = candidates.filter_method(
        &FieldFunction::contextual(move |_, arguments| {
            let key = arguments.first().unwrap_or(&FieldValue::Undefined);
            Ok((!key.model_property("expiresAt")?.is_truthy()
                || better_auth_core::query::field_compare(
                    &key.model_property("expiresAt")?,
                    &now,
                )? == Some(std::cmp::Ordering::Greater))
            .into())
        }),
        "candidates",
    )?;
    live.sort_method(
        &FieldFunction::contextual(|_, arguments| {
            let right = arguments
                .get(1)
                .unwrap_or(&FieldValue::Undefined)
                .model_property("createdAt")?
                .get_time_method("b.createdAt")?;
            let left = arguments
                .first()
                .unwrap_or(&FieldValue::Undefined)
                .model_property("createdAt")?
                .get_time_method("a.createdAt")?;
            Ok((better_auth_core::query::field_number(&right)?
                - better_auth_core::query::field_number(&left)?)
            .into())
        }),
        "candidates",
    )?
    .model_property("0")
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
