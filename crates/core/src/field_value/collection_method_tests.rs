#![expect(
    clippy::panic_in_result_fn,
    reason = "The contracts assert native callback arguments, sparse iteration, and error variants."
)]

use super::*;
use crate::{FieldMap, Utf16String};
use std::sync::{Arc, Mutex};

#[path = "collection_method_tests/sort.rs"]
mod sort;

#[test]
fn builtin_filter_captures_length_and_reads_present_indices_after_each_callback() -> AuthResult<()>
{
    let first: FieldValue = FieldMap::from([("native".into(), true.into())]).into();
    let array: FieldValue = FieldArray::with_length(5).into();
    array.set_model_property("0", first.clone())?;
    array.set_model_property("2", "before".into())?;
    array.set_model_property("3", FieldValue::Undefined)?;
    array.set_model_property("4", "last".into())?;
    let original = array.clone();
    let calls = Arc::new(Mutex::new(Vec::new()));
    let observed = calls.clone();
    let predicate = FieldFunction::contextual(move |receiver, arguments| {
        assert!(receiver.is_undefined());
        let [value, index, array] = arguments else {
            return Err(AuthError::internal(
                "Filter must receive value, index, and array",
            ));
        };
        assert!(array.strict_equals(&original));
        observed
            .lock()
            .map_err(|_| AuthError::internal("Filter observation lock poisoned"))?
            .push((index.clone(), value.clone()));
        if index.strict_equals(&0.into()) {
            original.set_model_property("2", "after".into())?;
            original.set_model_property("5", "outside captured length".into())?;
            Ok(FieldMap::new().into())
        } else if index.strict_equals(&2.into()) {
            Ok(0.into())
        } else {
            Ok("0".into())
        }
    });
    let filtered = array.filter_method(&predicate, "array")?;
    assert_eq!(
        filtered,
        vec![first.clone(), FieldValue::Undefined, "last".into()].into()
    );
    assert!(filtered.model_property("0")?.strict_equals(&first));
    assert!(!filtered.strict_equals(&array));
    let calls = calls
        .lock()
        .map_err(|_| AuthError::internal("Filter observation lock poisoned"))?;
    assert_eq!(
        *calls,
        [
            (0.into(), first.clone()),
            (2.into(), "after".into()),
            (3.into(), FieldValue::Undefined),
            (4.into(), "last".into())
        ]
    );
    assert!(
        calls
            .first()
            .is_some_and(|(_, value)| value.strict_equals(&first))
    );
    assert_eq!(array.model_property("length")?, 6.into());
    Ok(())
}

#[test]
fn own_noncallable_collection_methods_suppress_array_builtins() -> AuthResult<()> {
    let predicate = FieldFunction::contextual(|_, _| {
        Err(AuthError::internal(
            "A shadowed filter must not call the predicate",
        ))
    });
    for method in [
        FieldValue::Undefined,
        FieldValue::Null,
        false.into(),
        0.into(),
    ] {
        let array: FieldValue = vec!["key".into()].into();
        array.set_model_property("includes", method.clone())?;
        array.set_model_property("filter", method)?;
        assert!(matches!(
            array.includes_method(&"key".into(), "ids"),
            Err(AuthError::TypeError(message)) if message == "ids.includes is not a function"
        ));
        assert!(matches!(
            array.filter_method(&predicate, "ids"),
            Err(AuthError::TypeError(message)) if message == "ids.filter is not a function"
        ));
    }
    Ok(())
}

#[test]
fn string_properties_and_includes_use_utf16_units_and_canonical_indices() -> AuthResult<()> {
    for value in [FieldValue::from("A😀B"), Utf16String::from("A😀B").into()] {
        assert_eq!(value.model_property("length")?, 4.into());
        assert_eq!(value.model_property("0")?, "A".into());
        assert_eq!(
            value.model_property("1")?,
            Utf16String::from_units(vec![0xd83d]).into()
        );
        assert_eq!(
            value.model_property("2")?,
            Utf16String::from_units(vec![0xde00]).into()
        );
        for name in ["01", "+1", "1e0", "-0", "4", "4294967295"] {
            assert!(value.model_property(name)?.is_undefined(), "{name}");
        }
        for needle in [
            "".into(),
            "😀".into(),
            Utf16String::from_units(vec![0xde00]).into(),
        ] {
            assert_eq!(value.includes_method(&needle, "value")?, true.into());
        }
        assert_eq!(
            value.includes_method(&"missing".into(), "value")?,
            false.into()
        );
    }
    Ok(())
}

#[test]
fn builtin_map_preserves_holes_and_reads_later_values_after_the_callback() -> AuthResult<()> {
    let array: FieldValue = FieldArray::with_length(4).into();
    array.set_model_property("0", "first".into())?;
    array.set_model_property("2", FieldValue::Undefined)?;
    array.set_model_property("3", "before".into())?;
    let original = array.clone();
    let calls = Arc::new(Mutex::new(Vec::new()));
    let observed = calls.clone();
    let mapper = FieldFunction::contextual(move |receiver, arguments| {
        assert!(receiver.is_undefined());
        let [value, index, source] = arguments else {
            return Err(AuthError::internal(
                "Map must receive value, index, and array",
            ));
        };
        assert!(source.strict_equals(&original));
        observed
            .lock()
            .map_err(|_| AuthError::internal("Map observation lock poisoned"))?
            .push(index.clone());
        if index.strict_equals(&0.into()) {
            source.set_model_property("3", "after".into())?;
            source.set_model_property("4", "outside captured length".into())?;
        }
        Ok(value.clone())
    });
    let mapped = array.map_method(&mapper, "array", None)?;
    assert!(!mapped.strict_equals(&array));
    assert_eq!(mapped.model_property("length")?, 4.into());
    assert!(!mapped.has_property("1")?);
    assert!(mapped.has_property("2")?);
    assert_eq!(mapped.model_property("0")?, "first".into());
    assert!(mapped.model_property("2")?.is_undefined());
    assert_eq!(mapped.model_property("3")?, "after".into());
    assert_eq!(
        *calls
            .lock()
            .map_err(|_| AuthError::internal("Map observation lock poisoned"))?,
        [0.into(), 2.into(), 3.into()]
    );
    Ok(())
}

#[test]
fn builtin_concat_preserves_sparse_arrays_and_does_not_spread_other_values() -> AuthResult<()> {
    let child: FieldValue = FieldMap::from([("native".into(), true.into())]).into();
    let first: FieldValue = FieldArray::with_length(3).into();
    first.set_model_property("0", child.clone())?;
    first.set_model_property("2", FieldValue::Undefined)?;
    let second: FieldValue = FieldArray::with_length(2).into();
    second.set_model_property("1", child.clone())?;
    let result = first.concat_method(&[second.clone(), child.clone(), "xy".into()], "array")?;
    assert_eq!(result.model_property("length")?, 7.into());
    for name in ["1", "3"] {
        assert!(!result.has_property(name)?);
    }
    for name in ["0", "4", "5"] {
        assert!(result.model_property(name)?.strict_equals(&child));
    }
    assert!(result.has_property("2")?);
    assert!(result.model_property("2")?.is_undefined());
    assert_eq!(result.model_property("6")?, "xy".into());
    assert!(!result.strict_equals(&first));
    assert_eq!(first.model_property("length")?, 3.into());
    assert_eq!(second.model_property("length")?, 2.into());
    Ok(())
}

#[test]
fn custom_native_methods_receive_original_arguments_and_return_native_values() -> AuthResult<()> {
    for name in ["map", "concat", "sort", "at", "getTime"] {
        let value: FieldValue = crate::FieldDate::from_milliseconds(0.0).into();
        let result: FieldValue = FieldMap::from([("method".into(), name.into())]).into();
        let returned = result.clone();
        let calls = Arc::new(Mutex::new(Vec::new()));
        let observed = calls.clone();
        value.set_model_property(
            name,
            FieldFunction::contextual(move |receiver, arguments| {
                observed
                    .lock()
                    .map_err(|_| AuthError::internal("Method observation lock poisoned"))?
                    .push((receiver.clone(), arguments.to_vec()));
                Ok(returned.clone())
            })
            .into(),
        )?;
        let argument: FieldValue = match name {
            "map" | "sort" => FieldFunction::contextual(|_, _| {
                Err(AuthError::internal(
                    "Custom methods need not invoke callbacks",
                ))
            })
            .into(),
            _ => FieldMap::new().into(),
        };
        let actual = match (&argument, name) {
            (FieldValue::Function(callback), "map") => value.map_method(callback, "value", None)?,
            (FieldValue::Function(callback), "sort") => value.sort_method(callback, "value")?,
            (_, "concat") => value.concat_method(std::slice::from_ref(&argument), "value")?,
            (_, "getTime") => value.get_time_method("value")?,
            _ => value.at_method(&argument, "value")?,
        };
        assert!(actual.strict_equals(&result));
        let calls = std::mem::take(
            &mut *calls
                .lock()
                .map_err(|_| AuthError::internal("Method observation lock poisoned"))?,
        );
        let [(receiver, arguments)] = calls.as_slice() else {
            return Err(AuthError::internal("Custom method must run exactly once"));
        };
        assert!(receiver.strict_equals(&value));
        if name == "getTime" {
            assert!(arguments.is_empty());
        } else {
            let [actual_argument] = arguments.as_slice() else {
                return Err(AuthError::internal(
                    "Custom method must receive one original argument",
                ));
            };
            assert!(actual_argument.strict_equals(&argument));
        }
    }
    Ok(())
}

#[test]
fn builtin_at_captures_length_before_index_conversion_and_strings_retain_utf16() -> AuthResult<()> {
    let array: FieldValue = vec!["first".into(), "before".into()].into();
    let original = array.clone();
    let index: FieldValue = FieldMap::from([(
        "valueOf".into(),
        FieldFunction::contextual(move |_, _| {
            original.set_model_property("1", "after".into())?;
            original.set_model_property("2", "new last".into())?;
            Ok((-1).into())
        })
        .into(),
    )])
    .into();
    assert_eq!(array.at_method(&index, "array")?, "after".into());
    assert_eq!(
        array.at_method(&FieldValue::Number(f64::NAN), "array")?,
        "first".into()
    );
    for index in [f64::INFINITY, f64::NEG_INFINITY, -4.0, 3.0] {
        assert!(array.at_method(&index.into(), "array")?.is_undefined());
    }
    let text: FieldValue = "A😀".into();
    assert_eq!(
        text.at_method(&(-1).into(), "text")?,
        Utf16String::from_units(vec![0xde00]).into()
    );
    assert_eq!(
        text.at_method(&(-1.9).into(), "text")?,
        Utf16String::from_units(vec![0xde00]).into()
    );
    let tail: FieldValue = Utf16String::from_units(vec![0xd800]).into();
    assert_eq!(
        text.concat_method(&[tail, 7.into()], "text")?
            .display_utf16()?
            .as_utf16(),
        [65, 0xd83d, 0xde00, 0xd800, 55]
    );
    Ok(())
}

#[test]
fn get_time_keeps_invalid_dates_and_rejects_shadowed_builtins() -> AuthResult<()> {
    let value: FieldValue = crate::FieldDate::from_milliseconds(1234.0).into();
    assert_eq!(value.get_time_method("value")?, 1234.0.into());
    let invalid: FieldValue = crate::FieldDate::invalid().into();
    assert!(
        matches!(invalid.get_time_method("value")?, FieldValue::Number(value) if value.is_nan())
    );
    for method in [FieldValue::Undefined, FieldValue::Null, false.into()] {
        value.set_model_property("getTime", method)?;
        assert!(
            matches!(value.get_time_method("value"), Err(AuthError::TypeError(message)) if message == "value.getTime is not a function")
        );
    }
    Ok(())
}
