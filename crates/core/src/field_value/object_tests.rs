#![expect(
    clippy::panic_in_result_fn,
    reason = "Assertions compare shared identity and conversion boundaries; setup and source errors propagate."
)]

use super::*;
use crate::{SchemaField, SchemaValue};

#[test]
fn aliases_preserve_presence_and_property_order_through_mutation() -> AuthResult<()> {
    let object = FieldObject::from(FieldMap::from([
        ("first".into(), 1.into()),
        ("tail".into(), 2.into()),
        ("ownUndefined".into(), FieldValue::Undefined),
    ]));
    let alias = object.clone();
    assert_eq!(alias.get("absent")?, None);
    assert_eq!(alias.get("ownUndefined")?, Some(FieldValue::Undefined));
    assert_eq!(object.set("first", FieldValue::Null)?, Some(1.into()));
    assert_eq!(alias.delete("first")?, Some(FieldValue::Null));
    assert_eq!(object.set("first", false.into())?, None);
    assert_eq!(alias.delete("ownUndefined")?, Some(FieldValue::Undefined));
    assert_eq!(alias.delete("ownUndefined")?, None);
    assert_eq!(object.set("2", "two".into())?, None);
    assert_eq!(alias.set("1", "one".into())?, None);
    assert!(object.same_object(&alias));
    let value = FieldValue::Object(object);
    let expected = ["1", "2", "tail", "first"];
    assert_eq!(
        alias
            .snapshot_fields()?
            .keys()
            .map(String::as_str)
            .collect::<Vec<_>>(),
        expected
    );
    assert_eq!(
        value
            .enumerable_fields()?
            .keys()
            .map(String::as_str)
            .collect::<Vec<_>>(),
        expected
    );
    assert_eq!(
        value.json()?.and_then(|value| value
            .as_object()
            .map(|fields| fields.keys().cloned().collect::<Vec<_>>())),
        Some(expected.map(str::to_owned).to_vec())
    );
    assert_eq!(
        value.stringify()?.as_deref(),
        Some("{\"1\":\"one\",\"2\":\"two\",\"tail\":2,\"first\":false}")
    );
    Ok(())
}

#[test]
fn schema_decoding_preserves_handles_and_explicit_rust_copies_remain_available() -> AuthResult<()> {
    let object = FieldObject::from(FieldMap::from([("answer".into(), 1.into())]));
    let value = FieldValue::Object(object.clone());
    let json = SchemaValue::<serde_json::Value>::from_field(value.clone());
    let object_field = SchemaValue::<FieldObject>::from_field(value.clone());
    let value_field = SchemaValue::<FieldValue>::from_field(value.clone());
    assert!(matches!(json, SchemaValue::Dynamic(_)));
    assert!(object_field.typed()?.same_object(&object));
    assert!(value_field.typed()?.strict_equals(&value));
    let _ = object.set("answer", 2.into())?;
    assert_eq!(json.json()?, Some(serde_json::json!({"answer": 2})));
    assert!(json.field_value().strict_equals(&value));

    let array = FieldValue::from(vec![FieldValue::Number(1.0), FieldValue::Number(2.0)]);
    let vector = SchemaValue::<Vec<f64>>::from_field(array.clone());
    let optional = SchemaValue::<Option<Vec<f64>>>::from_field(array.clone());
    let json_array = SchemaValue::<serde_json::Value>::from_field(array.clone());
    for retained in [
        vector.field_value(),
        optional.field_value(),
        json_array.field_value(),
    ] {
        assert!(retained.strict_equals(&array));
    }
    assert!(matches!(vector, SchemaValue::Dynamic(_)));
    assert!(matches!(optional, SchemaValue::Dynamic(_)));
    assert_eq!(vector.field_value().decode::<Vec<f64>>()?, vec![1.0, 2.0]);
    assert_eq!(
        array.decode::<serde_json::Value>()?,
        serde_json::json!([1, 2])
    );

    let date = FieldDate::from_milliseconds(42.0);
    let date_field = SchemaValue::<FieldDate>::from_field(date.clone().into());
    assert!(date_field.typed()?.same_object(&date));
    assert_eq!(
        SchemaValue::<String>::from_field("ordinary".into()).typed()?,
        "ordinary"
    );
    assert_eq!(SchemaValue::<f64>::from_field(42.into()).typed()?, &42.0);
    assert_eq!(
        <Vec<f64> as SchemaField>::from_field(array),
        Ok(vec![1.0, 2.0])
    );
    Ok(())
}

#[test]
fn owned_cycles_have_finite_comparison_and_debug_but_require_explicit_unlinking() -> AuthResult<()>
{
    let left = FieldObject::from(FieldMap::from([("value".into(), 1.into())]));
    let right = FieldObject::from(FieldMap::from([("value".into(), 1.into())]));
    let _ = left.set("self", FieldValue::Object(left.clone()))?;
    let _ = right.set("self", FieldValue::Object(right.clone()))?;
    let equal = left == right;
    let debug = format!("{left:?}");
    let value = FieldValue::Object(left.clone());
    let json = value.json();
    let text = value.stringify();
    let clone = StructuredCloneContext::new().clone_value(&value);
    let _ = right.set("value", 2.into())?;
    let changed = left != right;
    // Break strong reference cycles before assertions or dropping the external handles.
    let _ = left.delete("self")?;
    let _ = right.delete("self")?;
    assert!(equal);
    assert!(changed);
    assert!(debug.contains("[Circular]"));
    assert!(
        matches!(json, Err(AuthError::TypeError(message)) if message == "Converting circular structure to JSON")
    );
    assert!(
        matches!(text, Err(AuthError::TypeError(message)) if message == "Converting circular structure to JSON")
    );
    let cloned = clone?;
    assert!(!cloned.strict_equals(&value));
    assert!(cloned.model_property("self")?.strict_equals(&cloned));
    assert_eq!(cloned.model_property("value")?, 1.into());
    let _ = cloned
        .as_object()
        .ok_or_else(|| AuthError::internal("Expected cloned object"))?
        .delete("self")?;
    Ok(())
}

#[test]
fn object_enumeration_preserves_descriptor_schedules_deletion_and_child_identity() -> AuthResult<()>
{
    use std::sync::Mutex;

    struct RestSource {
        fields: FieldObject,
        reads: Mutex<Vec<String>>,
    }

    impl FieldObjectSource for RestSource {
        fn own_keys(&self) -> AuthResult<Vec<String>> {
            self.reads
                .lock()
                .map_err(|_| AuthError::internal("Rest read events poisoned"))?
                .push("keys".into());
            self.fields.own_keys()
        }

        fn own_property_descriptor(
            &self,
            name: &str,
        ) -> AuthResult<Option<FieldPropertyDescriptor>> {
            if name == "excluded" {
                return Err(AuthError::internal("The excluded descriptor must not run"));
            }
            self.reads
                .lock()
                .map_err(|_| AuthError::internal("Rest read events poisoned"))?
                .push(format!("descriptor:{name}"));
            Ok(self
                .fields
                .own_property_descriptor(name)?
                .map(|mut descriptor| {
                    descriptor.enumerable = name != "hidden";
                    descriptor
                }))
        }

        fn get(&self, name: &str) -> AuthResult<Option<FieldValue>> {
            if matches!(name, "excluded" | "hidden") {
                return Err(AuthError::internal("The unselected getter must not run"));
            }
            self.reads
                .lock()
                .map_err(|_| AuthError::internal("Rest read events poisoned"))?
                .push(format!("get:{name}"));
            let value = self.fields.get(name)?;
            if name == "first" {
                let _ = self.fields.delete("deleted")?;
                let _ = self.fields.set("added", "not-enumerated".into())?;
            }
            Ok(value)
        }

        fn set(&self, name: String, value: FieldValue) -> AuthResult<Option<FieldValue>> {
            self.fields.set(name, value)
        }

        fn delete(&self, name: &str) -> AuthResult<Option<FieldValue>> {
            self.fields.delete(name)
        }

        fn snapshot_fields(&self) -> AuthResult<FieldMap> {
            Err(AuthError::internal(
                "Rest must read only selected properties",
            ))
        }

        fn identity(&self) -> usize {
            std::ptr::from_ref(self) as usize
        }
    }

    let child = FieldValue::from(FieldMap::from([("value".into(), 1.into())]));
    let source = || {
        Arc::new(RestSource {
            fields: FieldMap::from([
                ("excluded".into(), "unread".into()),
                ("first".into(), child.clone()),
                ("deleted".into(), "removed-by-first".into()),
                ("hidden".into(), "not-enumerable".into()),
                ("alias".into(), child.clone()),
                ("ownUndefined".into(), FieldValue::Undefined),
            ])
            .into(),
            reads: Mutex::default(),
        })
    };
    for operation in ["rest", "spread", "json", "keys"] {
        let source = source();
        if operation != "rest" {
            let _ = source.fields.delete("excluded")?;
        }
        let object = FieldObject::from_source(source.clone());
        let value = FieldValue::Object(object.clone());
        let expected = match operation {
            "json" => {
                assert_eq!(
                    value.json()?,
                    Some(serde_json::json!({
                        "first": {"value": 1}, "alias": {"value": 1},
                    }))
                );
                vec![
                    "get:toJSON",
                    "keys",
                    "descriptor:first",
                    "descriptor:deleted",
                    "descriptor:hidden",
                    "descriptor:alias",
                    "descriptor:ownUndefined",
                    "get:first",
                    "get:deleted",
                    "get:alias",
                    "get:ownUndefined",
                ]
            }
            "keys" => {
                assert_eq!(
                    object.enumerable_keys()?,
                    ["first", "deleted", "alias", "ownUndefined"]
                );
                vec![
                    "keys",
                    "descriptor:first",
                    "descriptor:deleted",
                    "descriptor:hidden",
                    "descriptor:alias",
                    "descriptor:ownUndefined",
                ]
            }
            _ => {
                let fields = if operation == "rest" {
                    value.enumerable_fields_except(&["excluded"])?
                } else {
                    value.enumerable_fields()?
                };
                assert_eq!(
                    fields.keys().map(String::as_str).collect::<Vec<_>>(),
                    ["first", "alias", "ownUndefined"]
                );
                assert!(fields["first"].strict_equals(&child));
                assert!(fields["alias"].strict_equals(&child));
                assert!(fields["ownUndefined"].is_undefined());
                vec![
                    "keys",
                    "descriptor:first",
                    "get:first",
                    "descriptor:deleted",
                    "descriptor:hidden",
                    "descriptor:alias",
                    "get:alias",
                    "descriptor:ownUndefined",
                    "get:ownUndefined",
                ]
            }
        };
        assert_eq!(
            *source
                .reads
                .lock()
                .map_err(|_| AuthError::internal("Rest read events poisoned"))?,
            expected,
            "{operation}",
        );
        if operation != "keys" {
            assert_eq!(source.fields.get("deleted")?, None);
            assert_eq!(source.fields.get("added")?, Some("not-enumerated".into()));
        }
    }
    Ok(())
}
