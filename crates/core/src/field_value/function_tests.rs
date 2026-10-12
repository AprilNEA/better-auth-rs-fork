use super::*;
use crate::{AuthError, FieldDate, FieldMap, user_fields::UserFieldFactory};
use std::sync::atomic::{AtomicUsize, Ordering};

#[test]
fn contextual_calls_preserve_handles_and_expose_callback_mutations() -> AuthResult<()> {
    let receiver = FieldValue::from(FieldMap::from([("remove".into(), true.into())]));
    let object = FieldValue::from(FieldMap::new());
    let arguments = [
        object.clone(),
        vec![object.clone()].into(),
        FieldDate::from_milliseconds(0.0).into(),
        FieldFunction::contextual(|_, _| {
            Err(AuthError::internal("Argument function must not run"))
        })
        .into(),
        FieldValue::Undefined,
        FieldValue::Null,
        "last".into(),
    ];
    let expected_receiver = receiver.clone();
    let expected_arguments = arguments.clone();
    let function = FieldFunction::contextual(move |receiver, arguments| {
        assert!(receiver.strict_equals(&expected_receiver));
        assert_eq!(arguments.len(), expected_arguments.len());
        for (actual, expected) in arguments.iter().zip(&expected_arguments) {
            assert!(actual.strict_equals(expected));
        }
        let FieldValue::Object(receiver) = receiver else {
            return Err(AuthError::internal("Expected an object receiver"));
        };
        assert_eq!(receiver.delete("remove")?, Some(true.into()));
        let [FieldValue::Object(object), result, _, next, ..] = arguments else {
            return Err(AuthError::internal("Expected the original arguments"));
        };
        assert!(receiver.set("next", next.clone())?.is_none());
        assert!(object.set("visited", true.into())?.is_none());
        Ok(result.clone())
    });
    let cloned = function.clone();
    assert_eq!(function, cloned);
    assert_eq!(function.identity(), cloned.identity());
    let returned = function.call_with(&receiver, &arguments)?;
    assert!(returned.strict_equals(&arguments[1]));
    assert!(receiver.model_property("remove")?.is_undefined());
    assert!(
        receiver
            .model_property("next")?
            .strict_equals(&arguments[3])
    );
    assert_eq!(object.model_property("visited")?, true.into());
    let FieldValue::Array(returned) = returned else {
        return Err(AuthError::internal("Expected the original array result"));
    };
    let child = returned
        .first()?
        .ok_or_else(|| AuthError::internal("Expected the original array child"))?;
    assert_eq!(child.model_property("visited")?, true.into());
    Ok(())
}

#[test]
fn calls_without_context_supply_undefined_and_no_arguments() -> AuthResult<()> {
    let function = FieldFunction::contextual(|receiver, arguments| {
        assert!(arguments.is_empty());
        Ok(receiver.clone())
    });
    assert!(function.call()?.is_undefined());
    assert!(function.call_with(&FieldValue::Null, &[])?.is_null());
    assert_ne!(
        function,
        FieldFunction::contextual(|receiver, _| Ok(receiver.clone()))
    );
    Ok(())
}

#[test]
fn repeated_factory_adaptation_keeps_identity_and_result_handles() -> AuthResult<()> {
    let result = FieldValue::from(FieldMap::new());
    let returned = result.clone();
    let factory: UserFieldFactory = UserFieldFactory::new(move || Ok(returned.clone()));
    let first = FieldFunction::from(factory.clone());
    let second = FieldFunction::from(factory.clone());
    assert_eq!(first, second);
    assert_eq!(first.identity(), factory.function().identity());
    assert_eq!(first.identity(), second.identity());
    assert!(first.call()?.strict_equals(&result));
    assert!(
        second
            .call_with(&FieldValue::Null, &["ignored".into()])?
            .strict_equals(&result)
    );
    let distinct: UserFieldFactory = UserFieldFactory::new(move || Ok(result.clone()));
    assert_ne!(first, FieldFunction::from(distinct));
    Ok(())
}

#[test]
fn calls_preserve_the_original_error_allocation() -> AuthResult<()> {
    for legacy in [false, true] {
        let allocation = Arc::new(AtomicUsize::new(0));
        let original = allocation.clone();
        let fail = move || -> AuthResult<FieldValue> {
            let message = "original-field-function-error".to_owned();
            original.store(message.as_ptr() as usize, Ordering::SeqCst);
            Err(AuthError::FieldInput {
                code: "CALL_REJECTED",
                message,
            })
        };
        let function = if legacy {
            FieldFunction::from(UserFieldFactory::new(fail))
        } else {
            FieldFunction::contextual(move |_, _| fail())
        };
        let result = function.call_with(&FieldValue::Null, &[false.into()]);
        let Err(AuthError::FieldInput { code, message }) = result else {
            return Err(AuthError::internal(
                "Expected the original field input error",
            ));
        };
        assert_eq!(code, "CALL_REJECTED");
        assert_eq!(message, "original-field-function-error");
        assert_eq!(message.as_ptr() as usize, allocation.load(Ordering::SeqCst));
    }
    Ok(())
}
