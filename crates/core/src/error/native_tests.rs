#![expect(
    clippy::panic_in_result_fn,
    reason = "Assertions verify constructor order, shared identity, and observable error propagation."
)]

use super::*;
use crate::{FieldFunction, FieldObject, field_value::FieldObjectSource};
use std::sync::{Arc, Mutex};

type ReadProperty = dyn Fn(&str) -> AuthResult<Option<FieldValue>> + Send + Sync;

struct Source {
    keys: Vec<String>,
    read: Box<ReadProperty>,
}

impl FieldObjectSource for Source {
    fn own_keys(&self) -> AuthResult<Vec<String>> {
        Ok(self.keys.clone())
    }

    fn get(&self, name: &str) -> AuthResult<Option<FieldValue>> {
        (self.read)(name)
    }

    fn set(&self, _: String, _: FieldValue) -> AuthResult<Option<FieldValue>> {
        Err(AuthError::type_error("The test source is read-only"))
    }

    fn delete(&self, _: &str) -> AuthResult<Option<FieldValue>> {
        Err(AuthError::type_error("The test source is read-only"))
    }

    fn snapshot_fields(&self) -> AuthResult<FieldMap> {
        let mut fields = FieldMap::new();
        for name in &self.keys {
            if let Some(value) = self.get(name)? {
                let _ = fields.insert(name.clone(), value);
            }
        }
        Ok(fields)
    }

    fn identity(&self) -> usize {
        self as *const Self as usize
    }
}

fn source(
    keys: &[&str],
    read: impl Fn(&str) -> AuthResult<Option<FieldValue>> + Send + Sync + 'static,
) -> FieldObject {
    FieldObject::from_source(Arc::new(Source {
        keys: keys.iter().map(|key| (*key).to_owned()).collect(),
        read: Box::new(read),
    }))
}

fn record(events: &Mutex<Vec<String>>, event: &str) -> AuthResult<()> {
    events
        .lock()
        .map_err(|_| AuthError::internal("Test events lock poisoned"))?
        .push(event.into());
    Ok(())
}

fn events(events: &Mutex<Vec<String>>) -> AuthResult<Vec<String>> {
    Ok(events
        .lock()
        .map_err(|_| AuthError::internal("Test events lock poisoned"))?
        .clone())
}

#[test]
fn raw_envelope_round_trip_keeps_identity_without_reading_fields() -> AuthResult<()> {
    let reads = Arc::new(Mutex::new(Vec::new()));
    let raw: FieldValue = source(&["name", "body", "statusCode"], {
        let reads = reads.clone();
        move |name| {
            record(&reads, name)?;
            Err(AuthError::type_error("No field should be read"))
        }
    })
    .into();
    let headers: FieldValue = FieldMap::from([("x-context".into(), "retained".into())]).into();
    let error = AuthError::from_thrown(raw.clone()).capture_native_headers(headers.clone());
    assert!(
        error
            .raw_value()
            .is_some_and(|value| value.strict_equals(&raw))
    );
    let _ = format!("{error:?} {error}");
    let response = error.to_auth_response();
    assert!(response.body.field_value()?.strict_equals(&raw));
    assert!(
        response
            .captured_headers_value()
            .is_some_and(|value| value.strict_equals(&headers))
    );
    let recovered = AuthError::from_returned_response(response)?;
    assert!(
        recovered
            .raw_value()
            .is_some_and(|value| value.strict_equals(&raw))
    );
    assert!(
        recovered
            .captured_headers_value()
            .is_some_and(|value| value.strict_equals(&headers))
    );
    assert!(events(&reads)?.is_empty());
    Ok(())
}

#[test]
fn structural_classification_repeats_reads_but_instance_brands_short_circuit() -> AuthResult<()> {
    let reads = Arc::new(Mutex::new(Vec::new()));
    let object = source(&["name"], {
        let reads = reads.clone();
        move |name| {
            record(&reads, name)?;
            let count = events(&reads)?.len();
            Ok(Some(if count == 1 {
                "APIError".into()
            } else {
                "Changed".into()
            }))
        }
    });
    let raw = FieldValue::Object(object);
    assert!(is_api_error_value(&raw)?);
    assert!(!is_api_error_value(&raw)?);
    assert_eq!(events(&reads)?, ["name", "name"]);

    let object = source(&["name"], |_| {
        Err(AuthError::type_error("name getter failed"))
    });
    assert!(object.has_property("name")?);
    let call = brand_api_error_object(object.clone(), ApiErrorClass::BetterCall);
    let auth = brand_api_error_object(object, ApiErrorClass::BetterAuth);
    assert!(is_api_error_value(&call)?);
    assert!(is_api_error_value(&auth)?);
    assert!(!api_error_instance(&call, ApiErrorClass::BetterAuth));
    assert!(api_error_instance(&auth, ApiErrorClass::BetterAuth));
    assert!(api_error_instance(&auth, ApiErrorClass::BetterCall));
    Ok(())
}

#[test]
fn status_reads_preserve_dynamic_values_and_do_not_coerce_objects() -> AuthResult<()> {
    let conversions = Arc::new(Mutex::new(Vec::new()));
    let dynamic: FieldValue = FieldMap::from([(
        "valueOf".into(),
        FieldFunction::contextual({
            let conversions = conversions.clone();
            move |_, _| {
                record(&conversions, "valueOf")?;
                Ok(409.0.into())
            }
        })
        .into(),
    )])
    .into();
    for value in [
        FieldValue::Undefined,
        FieldValue::Null,
        "409".into(),
        (-1.0).into(),
        400.75.into(),
        dynamic.clone(),
    ] {
        let raw: FieldValue = FieldMap::from([("statusCode".into(), value.clone())]).into();
        let error = AuthError::from_thrown(raw.clone());
        assert!(error.status_code()?.field_value().strict_equals(&value));
        let _ = raw
            .as_object()
            .ok_or_else(|| AuthError::internal("Expected raw error object"))?
            .set("statusCode", 201.0.into())?;
        assert_eq!(error.status_code()?, 201);
    }
    assert!(events(&conversions)?.is_empty());
    Ok(())
}

#[test]
fn construction_observes_defaults_then_arguments_then_message_conversion() -> AuthResult<()> {
    let reads = Arc::new(Mutex::new(Vec::new()));
    let status: FieldValue = FieldMap::from([(
        "toString".into(),
        FieldFunction::contextual({
            let reads = reads.clone();
            move |_, _| {
                record(&reads, "status.toString")?;
                Ok("BAD_REQUEST".into())
            }
        })
        .into(),
    )])
    .into();
    let message: FieldValue = FieldMap::from([(
        "toString".into(),
        FieldFunction::contextual({
            let reads = reads.clone();
            move |_, _| {
                record(&reads, "message.toString")?;
                Ok("captured message".into())
            }
        })
        .into(),
    )])
    .into();
    let cause: FieldValue = FieldMap::from([("source".into(), "original cause".into())]).into();
    let body: FieldValue = source(&["message", "cause"], {
        let reads = reads.clone();
        let cause = cause.clone();
        move |name| {
            record(&reads, &format!("body.{name}"))?;
            Ok(match name {
                "message" => Some(message.clone()),
                "cause" => Some(cause.clone()),
                _ => None,
            })
        }
    })
    .into();
    let headers: FieldValue = FieldMap::new().into();
    let error = AuthError::try_api_error(ApiErrorInit {
        status: status.clone(),
        body: body.clone(),
        headers: headers.clone(),
        ..Default::default()
    })?;
    assert_eq!(
        events(&reads)?,
        [
            "status.toString",
            "body.message",
            "body.cause",
            "body.cause",
            "message.toString"
        ]
    );
    assert_eq!(error.status_code()?, 400);
    assert!(error.status_value()?.strict_equals(&status));
    assert!(error.body_value()?.strict_equals(&body));
    assert!(error.headers_value()?.strict_equals(&headers));
    assert_eq!(error.instrumentation_message()?, "captured message");
    let raw = error
        .raw_value()
        .ok_or_else(|| AuthError::internal("Expected constructed error"))?;
    assert!(raw.model_property("cause")?.strict_equals(&cause));
    assert_eq!(events(&reads)?.len(), 5);
    Ok(())
}

#[test]
fn message_is_captured_once_without_serializing_the_body() -> AuthResult<()> {
    let body = FieldObject::from(FieldMap::from([
        ("message".into(), "initial message".into()),
        (
            "toJSON".into(),
            FieldFunction::contextual(|_, _| Err(AuthError::type_error("toJSON must not run")))
                .into(),
        ),
    ]));
    let error = AuthError::try_api_error(ApiErrorInit {
        body: body.clone().into(),
        ..Default::default()
    })?;
    let _ = body.set("message", "changed body".into())?;
    assert_eq!(error.instrumentation_message()?, "initial message");
    assert_eq!(
        error.body_value()?.model_property("message")?,
        "changed body".into()
    );
    Ok(())
}

#[test]
fn response_conversion_propagates_the_original_constructor_failure() -> AuthResult<()> {
    let failure: FieldValue = FieldMap::from([("failure".into(), "identity".into())]).into();
    let body: FieldValue = source(&["message"], {
        let failure = failure.clone();
        move |_| Err(AuthError::from_thrown(failure.clone()))
    })
    .into();
    let error = AuthError::from(crate::AuthResponse::native(Some(400), body));
    assert!(
        error
            .raw_value()
            .is_some_and(|value| value.strict_equals(&failure))
    );
    Ok(())
}

#[test]
fn instrumentation_propagates_top_level_message_getter_and_conversion_failures() -> AuthResult<()> {
    let failure: FieldValue = FieldMap::from([("failure".into(), "message".into())]).into();
    let getter: FieldValue = source(&["message"], {
        let failure = failure.clone();
        move |_| Err(AuthError::from_thrown(failure.clone()))
    })
    .into();
    let conversion: FieldValue = FieldMap::from([(
        "message".into(),
        FieldMap::from([(
            "toString".into(),
            FieldFunction::contextual({
                let failure = failure.clone();
                move |_, _| Err(AuthError::from_thrown(failure.clone()))
            })
            .into(),
        )])
        .into(),
    )])
    .into();
    for value in [getter, conversion] {
        let error = AuthError::from_thrown(value)
            .instrumentation_message()
            .err()
            .ok_or_else(|| AuthError::internal("Message conversion unexpectedly succeeded"))?;
        assert!(
            error
                .raw_value()
                .is_some_and(|value| value.strict_equals(&failure))
        );
    }
    Ok(())
}

#[test]
fn constructed_error_presence_and_enumeration_follow_error_properties() -> AuthResult<()> {
    let error = AuthError::try_api_error(ApiErrorInit {
        body: FieldMap::from([
            ("message".into(), "message".into()),
            ("cause".into(), true.into()),
        ])
        .into(),
        ..Default::default()
    })?;
    let object = error
        .raw_value()
        .and_then(FieldValue::as_object)
        .ok_or_else(|| AuthError::internal("Expected constructed error object"))?;
    assert!(object.has_property("message")?);
    assert!(object.has_property("cause")?);
    assert_eq!(
        object.own_keys()?,
        ["status", "body", "headers", "statusCode", "name"]
    );
    let _ = object.delete("cause")?;
    assert!(!object.has_property("cause")?);
    let _ = object.set("cause", false.into())?;
    assert_eq!(object.own_keys()?.last().map(String::as_str), Some("cause"));
    let _ = object.delete("message")?;
    assert!(object.has_property("message")?);
    assert_eq!(error.message_value()?, "".into());
    Ok(())
}

#[test]
fn constructor_defaults_distinguish_undefined_from_null_and_explicit_status_code() -> AuthResult<()>
{
    let default = AuthError::try_api_error(ApiErrorInit::default())?;
    assert_eq!(default.status_value()?, "INTERNAL_SERVER_ERROR".into());
    assert_eq!(default.status_code()?, 500);
    assert!(default.body_value()?.is_undefined());
    assert_eq!(default.message_value()?, "".into());

    let null = AuthError::try_api_error(ApiErrorInit {
        status: FieldValue::Null,
        status_code: FieldValue::Null,
        ..Default::default()
    })?;
    assert!(null.status_value()?.is_null());
    assert!(null.status_code()?.field_value().is_null());
    let dynamic: FieldValue = FieldMap::new().into();
    let explicit = AuthError::try_api_error(ApiErrorInit {
        status: source(&["toString"], |_| {
            Err(AuthError::type_error("status must not convert"))
        })
        .into(),
        status_code: dynamic.clone(),
        ..Default::default()
    })?;
    assert!(
        explicit
            .status_code()?
            .field_value()
            .strict_equals(&dynamic)
    );
    let unknown = AuthError::try_api_error(ApiErrorInit {
        status: "UNKNOWN".into(),
        ..Default::default()
    })?;
    assert!(unknown.status_code()?.is_undefined());
    Ok(())
}
