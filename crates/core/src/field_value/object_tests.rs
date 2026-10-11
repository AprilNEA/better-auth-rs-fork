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
