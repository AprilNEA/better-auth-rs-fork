use std::collections::HashMap;
use std::sync::{Arc, OnceLock, Weak};

use better_auth_core::{
    ApiKey, AuthError, AuthResult, FieldFunction, FieldValue, Utf16String,
    query::{field_number, field_string_units},
    store::SecondaryStorage,
};
use tokio::sync::Mutex;

type ReferenceLocks = std::sync::Mutex<HashMap<Vec<u16>, Weak<Mutex<()>>>>;

pub(super) fn cache_key(prefix: &str, value: &FieldValue) -> AuthResult<FieldValue> {
    let mut units = prefix.encode_utf16().collect::<Vec<_>>();
    units.extend_from_slice(value.display_utf16()?.as_utf16());
    Ok(Utf16String::from_units(units).into())
}

pub(super) async fn read(
    storage: Arc<dyn SecondaryStorage>,
    key: &FieldValue,
) -> AuthResult<FieldValue> {
    Ok(match storage.invoke_get_native(key.clone())?.await? {
        // The upstream catch applies only to JSON.parse, not to later method calls.
        Some(value @ (FieldValue::String(_) | FieldValue::Utf16String(_))) => {
            better_auth_core::utils::json::parse_native_json(&value)
                .unwrap_or_else(|_| Vec::<FieldValue>::new().into())
        }
        Some(value @ FieldValue::Array(_)) => value,
        _ => Vec::<FieldValue>::new().into(),
    })
}

pub(in crate::plugins::api_key) fn property(
    value: &FieldValue,
    name: &str,
) -> AuthResult<FieldValue> {
    value.model_property(name)
}

pub(super) fn has_entries(value: &FieldValue) -> AuthResult<bool> {
    Ok(field_number(&property(value, "length")?)? > 0.0)
}

pub(super) enum Items {
    Complete(Vec<FieldValue>),
    Indexed { count: f64, concurrency: usize },
}

pub(super) fn items(value: &FieldValue) -> AuthResult<Items> {
    let length = property(value, "length")?;
    let count = field_number(&length)?;
    if length.is_number()
        && (!count.is_finite() || count < 0.0 || count.fract() != 0.0 || count > u32::MAX as f64)
    {
        return Err(AuthError::internal(
            "Array length must be a positive integer of safe magnitude.",
        ));
    }
    if length.is_number() && count == 0.0 {
        return Ok(Items::Complete(Vec::new()));
    }
    if count.is_nan() || count < 1.0 {
        // A nonnumeric Array constructor argument remains an element when no worker starts.
        return Ok(Items::Complete(vec![length]));
    }
    Ok(Items::Indexed {
        count,
        concurrency: count.min(super::STORAGE_CONCURRENCY as f64).floor() as usize,
    })
}

fn next(value: FieldValue, id: &FieldValue, insert: bool) -> AuthResult<FieldValue> {
    if !insert {
        let id = id.clone();
        let predicate = FieldFunction::contextual(move |_, arguments| {
            Ok((!arguments
                .first()
                .unwrap_or(&FieldValue::Undefined)
                .strict_equals(&id))
            .into())
        });
        return value.filter_method(&predicate, "ids");
    }
    if value.includes_method(id, "ids")?.is_truthy() {
        return Ok(value);
    }
    if let FieldValue::Array(values) = &value {
        let mut values = values.snapshot()?;
        values.push(id.clone());
        return Ok(values.into());
    }
    if let Some(units) = field_string_units(&value) {
        // String iteration yields code points; indexed reads yield UTF-16 code units.
        let mut values = char::decode_utf16(units.iter().copied())
            .map(|value| match value {
                Ok(value) => value.to_string().into(),
                Err(error) => Utf16String::from_units(vec![error.unpaired_surrogate()]).into(),
            })
            .collect::<Vec<FieldValue>>();
        values.push(id.clone());
        return Ok(values.into());
    }
    Err(AuthError::type_error("ids is not iterable"))
}

pub(super) async fn modify_reference(
    storage: Arc<dyn SecondaryStorage>,
    key: &ApiKey,
    index: FieldValue,
    insert: bool,
) -> AuthResult<()> {
    // The upstream lock coordinates reference-list writers only within this process.
    let units = index.display_utf16()?.as_utf16().to_vec();
    static LOCKS: OnceLock<ReferenceLocks> = OnceLock::new();
    let lock = {
        let mut locks = LOCKS
            .get_or_init(Default::default)
            .lock()
            .map_err(|_| AuthError::internal("API key reference-list lock poisoned"))?;
        locks.retain(|_, lock| lock.strong_count() > 0);
        match locks.get(&units).and_then(Weak::upgrade) {
            Some(lock) => lock,
            None => {
                let lock = Arc::new(Mutex::new(()));
                let _ = locks.insert(units, Arc::downgrade(&lock));
                lock
            }
        }
    };
    let _guard = lock.lock().await;
    // Promise.then defers the reference read even when the previous lock owner completed.
    better_auth_core::request_runtime::concurrent::adapter_result(Ok(())).await?;
    let value = next(
        read(storage.clone(), &index).await?,
        &key.id.field_value(),
        insert,
    )?;
    if property(&value, "length")?.strict_equals(&0.0.into()) {
        storage.invoke_delete_native(index)?.await
    } else {
        storage
            .invoke_set_native(index, value.stringify_native()?, None)?
            .await
    }
}

#[cfg(test)]
mod tests;
