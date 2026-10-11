#![expect(
    clippy::panic_in_result_fn,
    reason = "The contracts assert receiver identity, method scheduling, and original errors; setup failures propagate."
)]

use super::*;
use crate::{FieldFunction, FieldMap, FieldObject};
use std::sync::{Arc, Mutex};

#[test]
fn hint_selects_the_first_primitive_method_with_the_original_receiver() -> AuthResult<()> {
    for (hint, expected) in [
        (PrimitiveHint::String, "toString"),
        (PrimitiveHint::Number, "valueOf"),
        (PrimitiveHint::Default, "valueOf"),
    ] {
        let object = FieldObject::from(FieldMap::new());
        let identity = object.identity();
        let events = Arc::new(Mutex::new(Vec::new()));
        for name in ["toString", "valueOf"] {
            let events = events.clone();
            let _ = object.set(
                name,
                FieldFunction::contextual(move |receiver, arguments| {
                    let FieldValue::Object(receiver) = receiver else {
                        return Err(AuthError::internal("Primitive receiver is not the object"));
                    };
                    assert_eq!(receiver.identity(), identity);
                    assert!(arguments.is_empty());
                    events
                        .lock()
                        .map_err(|_| AuthError::internal("Primitive event lock poisoned"))?
                        .push(name);
                    Ok(name.into())
                })
                .into(),
            )?;
        }
        assert_eq!(FieldValue::Object(object).primitive(hint)?, expected.into());
        assert_eq!(
            *events
                .lock()
                .map_err(|_| AuthError::internal("Primitive event lock poisoned"))?,
            [expected]
        );
    }
    Ok(())
}

#[test]
fn fallback_observes_method_replacement_and_rejects_all_object_results() -> AuthResult<()> {
    for result in [
        FieldValue::from(FieldMap::new()),
        FieldValue::from(Vec::<FieldValue>::new()),
        crate::FieldDate::from_milliseconds(0.0).into(),
        FieldFunction::contextual(|_, _| {
            Err(AuthError::internal(
                "Returned functions must not be invoked",
            ))
        })
        .into(),
    ] {
        let object = FieldObject::from(FieldMap::new());
        let _ = object.set(
            "toString",
            FieldFunction::contextual(|_, _| {
                Err(AuthError::internal("Replaced method must not be invoked"))
            })
            .into(),
        )?;
        let _ = object.set(
            "valueOf",
            FieldFunction::contextual(move |receiver, _| {
                let FieldValue::Object(receiver) = receiver else {
                    return Err(AuthError::internal("Primitive receiver is not the object"));
                };
                let _ = receiver.set(
                    "toString",
                    FieldFunction::contextual(|_, _| Ok(FieldValue::Undefined)).into(),
                )?;
                Ok(result.clone())
            })
            .into(),
        )?;
        assert!(
            FieldValue::Object(object)
                .primitive(PrimitiveHint::Number)?
                .is_undefined()
        );
    }
    Ok(())
}

#[test]
fn noncallable_properties_suppress_builtins_and_callback_errors_stay_original() -> AuthResult<()> {
    let fallback = FieldFunction::contextual(|_, _| Ok(FieldValue::Number(-0.0)));
    for first in [FieldValue::Undefined, FieldValue::Null, false.into()] {
        let value = FieldValue::from(FieldMap::from([
            ("toString".into(), first.clone()),
            ("valueOf".into(), fallback.clone().into()),
        ]));
        let primitive = value.primitive(PrimitiveHint::String)?;
        assert!(
            matches!(primitive, FieldValue::Number(number) if number == 0.0 && number.is_sign_negative())
        );
        let value = FieldValue::from(FieldMap::from([
            ("toString".into(), first),
            ("valueOf".into(), FieldValue::Null),
        ]));
        assert!(
            matches!(value.primitive(PrimitiveHint::String), Err(AuthError::TypeError(message)) if message == "No default value")
        );
    }
    let message = String::from("primitive callback original error");
    let original = message.as_ptr() as usize;
    let failure = Mutex::new(Some(message));
    let value = FieldValue::from(FieldMap::from([
        (
            "valueOf".into(),
            FieldFunction::contextual(move |_, _| {
                let message = failure
                    .lock()
                    .map_err(|_| AuthError::internal("Primitive error lock poisoned"))?
                    .take()
                    .ok_or_else(|| AuthError::internal("Primitive callback repeated"))?;
                Err(AuthError::internal(message))
            })
            .into(),
        ),
        (
            "toString".into(),
            FieldFunction::contextual(|_, _| {
                Err(AuthError::internal("Fallback ran after the original error"))
            })
            .into(),
        ),
    ]));
    let result = value.primitive(PrimitiveHint::Number);
    assert!(
        matches!(result, Err(AuthError::Internal(message)) if message.as_ptr() as usize == original)
    );
    Ok(())
}

#[test]
fn public_conversions_share_hints_and_evaluate_operands_left_to_right() -> AuthResult<()> {
    let events = Arc::new(Mutex::new(Vec::new()));
    let operand = |name: &'static str| {
        let fields = ["valueOf", "toString"].map(|method| {
            let events = events.clone();
            (
                method.into(),
                FieldFunction::contextual(move |_, _| {
                    events
                        .lock()
                        .map_err(|_| AuthError::internal("Primitive event lock poisoned"))?
                        .push((name, method));
                    Ok(if method == "valueOf" {
                        42.0.into()
                    } else {
                        "2030-01-01T00:00:00.000Z".into()
                    })
                })
                .into(),
            )
        });
        FieldValue::from(FieldMap::from(fields))
    };
    let left = operand("left");
    let right = operand("right");
    assert_eq!(left.display_utf16()?, "2030-01-01T00:00:00.000Z".into());
    assert_eq!(crate::query::field_number(&left)?, 42.0);
    assert_eq!(
        crate::query::field_compare(&left, &right)?,
        Some(std::cmp::Ordering::Equal)
    );
    assert_eq!(crate::query::field_add(&left, &right)?, 84.0.into());
    assert_eq!(crate::query::field_date(&left)?.milliseconds(), 42.0);
    assert_eq!(
        *events
            .lock()
            .map_err(|_| AuthError::internal("Primitive event lock poisoned"))?,
        [
            ("left", "toString"),
            ("left", "valueOf"),
            ("left", "valueOf"),
            ("right", "valueOf"),
            ("left", "valueOf"),
            ("right", "valueOf"),
            ("left", "valueOf"),
        ]
    );
    Ok(())
}
