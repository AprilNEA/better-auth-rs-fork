use crate::{AuthResult, FieldMap, FieldValue, FromFieldMap};

#[cfg(test)]
mod tests;
#[cfg(test)]
mod verification_contract;

pub(super) fn decode(value: Option<FieldValue>) -> AuthResult<Option<FieldValue>> {
    value
        .map(|value| crate::utils::json::safe_parse_field(&value))
        .transpose()
        .map(|value| value.filter(FieldValue::is_truthy))
}

pub(super) fn parse(value: Option<FieldValue>) -> AuthResult<Option<FieldValue>> {
    value
        .map(|value| match value {
            FieldValue::String(_) | FieldValue::Utf16String(_) => {
                crate::utils::json::parse_native_json(&value)
            }
            value => Ok(value),
        })
        .transpose()
        .map(|value| value.filter(FieldValue::is_truthy))
}

pub(super) fn dated_fields(
    source: impl Fn() -> AuthResult<FieldValue>,
    dates: &[&str],
) -> AuthResult<FieldMap> {
    let mut fields = source()?.enumerable_fields()?;
    for name in dates {
        let date = crate::query::field_date(&source()?.model_property(name)?)?;
        let _ = fields.insert((*name).into(), date.into());
    }
    Ok(fields)
}

pub(super) fn session(fields: FieldMap) -> AuthResult<crate::SessionView> {
    let mut session = crate::SessionView::from_field_values(fields)?;
    session.active = true;
    Ok(session)
}

pub(super) fn user(cached: &FieldValue) -> AuthResult<crate::UserView> {
    crate::UserView::from_field_values(dated_fields(
        || cached.model_property("user"),
        &["createdAt", "updatedAt"],
    )?)
}

pub(super) fn consumed_verification(
    raw: Option<FieldValue>,
) -> AuthResult<Option<crate::VerificationView>> {
    let Some(raw) = raw.filter(FieldValue::is_truthy) else {
        return Ok(None);
    };
    let candidate = match raw {
        FieldValue::String(_) | FieldValue::Utf16String(_) => {
            crate::utils::json::safe_parse_field(&raw)?
        }
        FieldValue::Object(_) | FieldValue::Array(_) | FieldValue::Date(_) => raw,
        _ => return Ok(None),
    };
    if !candidate.is_truthy() {
        return Ok(None);
    }
    let expires_at = crate::query::field_date(&candidate.model_property("expiresAt")?)?;
    if !expires_at.milliseconds().is_finite() {
        return Ok(None);
    }
    let mut fields = candidate.enumerable_fields()?;
    let _ = fields.insert("expiresAt".into(), expires_at.into());
    crate::VerificationView::from_fields(fields).map(Some)
}

pub(super) fn session_envelope(session: FieldMap, user: Option<crate::UserView>) -> FieldValue {
    FieldMap::from([
        ("session".into(), session.into()),
        (
            "user".into(),
            user.map_or(FieldValue::Null, |user| FieldMap::from(user).into()),
        ),
    ])
    .into()
}
