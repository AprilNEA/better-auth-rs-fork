#![expect(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "Find contracts assert exact builtin callback arguments and complete captured observations."
)]

use super::*;

#[test]
fn find_visits_holes_and_captures_length_before_live_mutations() -> AuthResult<()> {
    let selected: FieldValue = FieldMap::from([("id".into(), "selected".into())]).into();
    let array: FieldValue = FieldArray::with_length(4).into();
    array.set_model_property("0", "first".into())?;
    array.set_model_property("2", "before".into())?;
    array.set_model_property("3", "deleted".into())?;
    let original = array.clone();
    let replacement = selected.clone();
    let calls = Arc::new(Mutex::new(Vec::new()));
    let observed = calls.clone();
    let predicate = FieldFunction::contextual(move |receiver, arguments| {
        assert!(receiver.is_undefined());
        let [value, index, source] = arguments else {
            return Err(AuthError::internal(
                "Find must receive value, index, and array",
            ));
        };
        assert!(source.strict_equals(&original));
        observed
            .lock()
            .unwrap()
            .push((index.clone(), value.clone()));
        if index.strict_equals(&0.into()) {
            source.set_model_property("2", replacement.clone())?;
            source.set_model_property("length", 3.into())?;
            source.set_model_property("4", "outside captured length".into())?;
        }
        Ok(false.into())
    });
    assert!(array.find_method(&predicate, "array")?.is_undefined());
    assert_eq!(
        *calls.lock().unwrap(),
        [
            (0.into(), "first".into()),
            (1.into(), FieldValue::Undefined),
            (2.into(), selected.clone()),
            (3.into(), FieldValue::Undefined),
        ]
    );
    let target = selected.clone();
    let predicate = FieldFunction::contextual(move |_, arguments| {
        let value = &arguments[0];
        if arguments[1].strict_equals(&3.into()) {
            return Err(AuthError::internal("Find must stop after a match"));
        }
        Ok(value.strict_equals(&target).into())
    });
    assert!(
        array
            .find_method(&predicate, "array")?
            .strict_equals(&selected)
    );
    Ok(())
}

#[test]
fn find_propagates_original_predicate_errors_and_keeps_completed_mutations() -> AuthResult<()> {
    let original: FieldValue = FieldMap::from([("failure".into(), "predicate".into())]).into();
    let failure = original.clone();
    let array: FieldValue = vec![0.into(), 1.into()].into();
    let predicate = FieldFunction::contextual(move |_, arguments| {
        arguments[2].set_model_property("0", "written".into())?;
        Err(AuthError::from_thrown(failure.clone()))
    });
    let error = array.find_method(&predicate, "array").unwrap_err();
    assert!(error.into_thrown_value()?.strict_equals(&original));
    assert_eq!(array.model_property("0")?, "written".into());
    assert_eq!(array.model_property("1")?, 1.into());
    Ok(())
}
