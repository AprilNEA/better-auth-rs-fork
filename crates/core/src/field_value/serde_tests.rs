#![expect(
    clippy::panic_in_result_fn,
    reason = "Contracts assert getter scheduling and original error allocation; setup failures propagate."
)]

use super::*;
use crate::field_value::{FieldObject, FieldObjectSource};
use std::sync::{
    Arc, Mutex, MutexGuard,
    atomic::{AtomicUsize, Ordering},
};

type Getter = dyn Fn(&str) -> AuthResult<()> + Send + Sync;

struct Source {
    fields: Mutex<FieldMap>,
    getter: Box<Getter>,
}

impl Source {
    fn fields(&self) -> AuthResult<MutexGuard<'_, FieldMap>> {
        self.fields
            .lock()
            .map_err(|_| AuthError::internal("JSON source lock poisoned"))
    }
}

impl FieldObjectSource for Source {
    fn own_keys(&self) -> AuthResult<Vec<String>> {
        Ok(self.fields()?.keys().cloned().collect())
    }

    fn get(&self, name: &str) -> AuthResult<Option<FieldValue>> {
        if !self.fields()?.contains_key(name) {
            return Ok(None);
        }
        (self.getter)(name)?;
        Ok(self.fields()?.get(name).cloned())
    }

    fn set(&self, name: String, value: FieldValue) -> AuthResult<Option<FieldValue>> {
        Ok(self.fields()?.insert(name, value))
    }

    fn delete(&self, name: &str) -> AuthResult<Option<FieldValue>> {
        Ok(self.fields()?.remove(name))
    }

    fn snapshot_fields(&self) -> AuthResult<FieldMap> {
        Err(AuthError::internal(
            "JSON must read one property before traversing its value",
        ))
    }

    fn identity(&self) -> usize {
        std::ptr::from_ref(self) as usize
    }
}

#[test]
fn json_reads_children_before_later_properties_and_preserves_original_errors() -> AuthResult<()> {
    for encoded in [false, true] {
        for fail in [false, true] {
            let events = Arc::new(Mutex::new(Vec::new()));
            let original = Arc::new(AtomicUsize::new(0));
            let outer = Arc::new(Source {
                fields: Mutex::new(FieldMap::new()),
                getter: Box::new({
                    let events = events.clone();
                    move |name| {
                        events
                            .lock()
                            .map_err(|_| AuthError::internal("JSON event lock poisoned"))?
                            .push(format!("outer.{name}"));
                        Ok(())
                    }
                }),
            });
            let child = Arc::new(Source {
                fields: Mutex::new([("value".into(), 1.into())].into()),
                getter: Box::new({
                    let outer = Arc::downgrade(&outer);
                    let events = events.clone();
                    let original = original.clone();
                    move |name| {
                        events
                            .lock()
                            .map_err(|_| AuthError::internal("JSON event lock poisoned"))?
                            .push(format!("child.{name}"));
                        if fail {
                            let message = "JSON getter original error".to_owned();
                            original.store(message.as_ptr() as usize, Ordering::SeqCst);
                            return Err(AuthError::internal(message));
                        }
                        let outer = outer
                            .upgrade()
                            .ok_or_else(|| AuthError::internal("Missing JSON parent"))?;
                        let mut fields = outer.fields()?;
                        let _ = fields.insert("tail".into(), "after".into());
                        let _ = fields.remove("drop");
                        let _ = fields.insert("added".into(), true.into());
                        Ok(())
                    }
                }),
            });
            *outer.fields()? = [
                ("child".into(), FieldObject::from_source(child).into()),
                ("tail".into(), "before".into()),
                ("drop".into(), true.into()),
            ]
            .into();
            let value = FieldValue::from(FieldObject::from_source(outer.clone()));
            let result = if encoded {
                value.stringify()
            } else {
                value.json().and_then(|value| {
                    value
                        .map(|value| serde_json::to_string(&value).map_err(Into::into))
                        .transpose()
                })
            };
            if fail {
                assert!(matches!(result, Err(AuthError::Internal(message))
                    if message == "JSON getter original error" && message.as_ptr() as usize == original.load(Ordering::SeqCst)));
                assert_eq!(
                    *events
                        .lock()
                        .map_err(|_| AuthError::internal("JSON event lock poisoned"))?,
                    ["outer.child", "child.value"]
                );
                assert_eq!(
                    outer.fields()?.get("tail"),
                    Some(&FieldValue::from("before"))
                );
            } else {
                assert_eq!(
                    result?,
                    Some(r#"{"child":{"value":1},"tail":"after"}"#.into())
                );
                assert_eq!(
                    *events
                        .lock()
                        .map_err(|_| AuthError::internal("JSON event lock poisoned"))?,
                    ["outer.child", "child.value", "outer.tail"]
                );
                assert_eq!(
                    outer
                        .fields()?
                        .keys()
                        .map(String::as_str)
                        .collect::<Vec<_>>(),
                    ["child", "tail", "added"]
                );
                assert_eq!(
                    outer.fields()?.get("tail"),
                    Some(&FieldValue::from("after"))
                );
                assert_eq!(outer.fields()?.get("added"), Some(&FieldValue::from(true)));
            }
        }
    }
    Ok(())
}
