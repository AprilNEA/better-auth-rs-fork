use crate::{AuthError, AuthResult, FieldArray, FieldFunction, FieldMap, FieldValue};

pub(super) fn empty() -> FieldValue {
    FieldArray::new().into()
}

pub(super) fn new(token: FieldValue, expires_at: FieldValue) -> FieldValue {
    FieldMap::from([("token".into(), token), ("expiresAt".into(), expires_at)]).into()
}

pub(super) fn filter(
    value: &FieldValue,
    keep: impl Fn(&FieldValue) -> AuthResult<bool> + Send + Sync + 'static,
) -> AuthResult<FieldValue> {
    value.filter_method(
        &FieldFunction::contextual(move |_, arguments| {
            keep(arguments.first().unwrap_or(&FieldValue::Undefined)).map(Into::into)
        }),
        "list",
    )
}

pub(super) fn tokens(value: &FieldValue) -> AuthResult<FieldValue> {
    value.map_method(
        &FieldFunction::contextual(|_, arguments| {
            arguments
                .first()
                .unwrap_or(&FieldValue::Undefined)
                .model_property("token")
        }),
        "sessionReferences",
        None,
    )
}

pub(super) fn iter(
    value: &FieldValue,
) -> AuthResult<Box<dyn Iterator<Item = AuthResult<FieldValue>> + Send>> {
    if let FieldValue::Array(array) = value {
        let array = array.clone();
        let mut index = 0;
        let mut finished = false;
        return Ok(Box::new(std::iter::from_fn(move || {
            if finished {
                return None;
            }
            let length = match array.len() {
                Ok(length) => length,
                Err(error) => {
                    finished = true;
                    return Some(Err(error));
                }
            };
            if index >= length {
                finished = true;
                return None;
            }
            let value = array.get(index).map(Option::unwrap_or_default);
            index += 1;
            Some(value)
        })));
    }
    let units = match value {
        FieldValue::String(text) => text.encode_utf16().collect::<Vec<_>>(),
        FieldValue::Utf16String(text) => text.as_utf16().to_vec(),
        _ => return Err(AuthError::type_error("list is not iterable")),
    };
    let values = char::decode_utf16(units)
        .map(|value| match value {
            Ok(value) => value.to_string().into(),
            Err(error) => crate::Utf16String::from_units(vec![error.unpaired_surrogate()]).into(),
        })
        .collect::<Vec<FieldValue>>();
    Ok(Box::new(values.into_iter().map(Ok)))
}

pub(super) fn sort(value: &FieldValue) -> AuthResult<FieldValue> {
    value.sort_method(
        &FieldFunction::contextual(|_, arguments| {
            let left = arguments
                .first()
                .unwrap_or(&FieldValue::Undefined)
                .model_property("expiresAt")?;
            let right = arguments
                .get(1)
                .unwrap_or(&FieldValue::Undefined)
                .model_property("expiresAt")?;
            let difference =
                crate::query::field_number(&left)? - crate::query::field_number(&right)?;
            Ok(difference.into())
        }),
        "references",
    )
}

pub(super) fn last_expiration(value: &FieldValue) -> AuthResult<FieldValue> {
    let last = value.at_method(&(-1).into(), "references")?;
    if last.is_null() || last.is_undefined() {
        Ok(FieldValue::Undefined)
    } else {
        last.model_property("expiresAt")
    }
}

pub(super) fn encode(value: &FieldValue) -> AuthResult<String> {
    super::cache::stringify(value)
}
