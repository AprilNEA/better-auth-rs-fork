//! Preserve native JOSE claims until NumericDate setters or JWT serialization consume them.

use crate::{AuthError, AuthResult, FieldMap, FieldValue};
use chrono::Utc;
use std::sync::LazyLock;

/// Apply a JOSE NumericDate setter to a number, Date, or relative time string.
pub fn numeric_date(value: &FieldValue, setter: &str) -> AuthResult<FieldValue> {
    let numeric = match value {
        FieldValue::Number(value) => Some(*value),
        FieldValue::Date(value) => Some((value.milliseconds() / 1000.0).floor()),
        _ => None,
    };
    if let Some(value) = numeric {
        return if value.is_finite() {
            Ok(value.into())
        } else {
            Err(AuthError::type_error(format!("Invalid {setter} input")))
        };
    }
    static PERIOD: LazyLock<Result<regex::Regex, regex::Error>> = LazyLock::new(|| {
        regex::Regex::new(
            r"(?i)^(\+|\-)? ?([0-9]+|[0-9]+\.[0-9]+) ?(seconds?|secs?|s|minutes?|mins?|m|hours?|hrs?|h|days?|d|weeks?|w|years?|yrs?|y)(?: (ago|from now))?(?:\r\n|[\n\r\u{2028}\u{2029}])?$",
        )
    });
    let invalid = || AuthError::type_error("Invalid time period format");
    let period = PERIOD
        .as_ref()
        .map_err(|error| AuthError::internal(error.to_string()))?;
    let captures = value
        .as_str()
        .and_then(|value| period.captures(value))
        .ok_or_else(invalid)?;
    if captures.get(1).is_some() && captures.get(4).is_some() {
        return Err(invalid());
    }
    let amount: f64 = captures
        .get(2)
        .ok_or_else(invalid)?
        .as_str()
        .parse()
        .map_err(|_| invalid())?;
    let unit = captures
        .get(3)
        .and_then(|value| value.as_str().as_bytes().first())
        .ok_or_else(invalid)?;
    let scale = match unit.to_ascii_lowercase() {
        b's' => 1.0,
        b'm' => 60.0,
        b'h' => 3600.0,
        b'd' => 86400.0,
        b'w' => 604800.0,
        b'y' => 31557600.0,
        _ => return Err(invalid()),
    };
    let seconds = (amount * scale + 0.5).floor();
    if !seconds.is_finite() {
        return Err(invalid());
    }
    let negative = captures.get(1).is_some_and(|value| value.as_str() == "-")
        || captures.get(4).is_some_and(|value| value.as_str() == "ago");
    Ok((Utc::now().timestamp() as f64 + if negative { -seconds } else { seconds }).into())
}

/// Encode a prepared JOSE payload after checking the three NumericDate claims.
/// Clone at the builder boundary before calling setters or this serializer.
pub fn serialize_claims(payload: FieldMap) -> AuthResult<String> {
    for name in ["iat", "nbf", "exp"] {
        if let Some(FieldValue::Number(value)) = payload.get(name)
            && !value.is_finite()
        {
            return Err(AuthError::type_error(format!(
                "\"{name}\" claim must be a finite number"
            )));
        }
    }
    FieldValue::from(payload)
        .stringify()?
        .ok_or_else(|| AuthError::type_error("JWT Claims Set is not valid JSON"))
}
