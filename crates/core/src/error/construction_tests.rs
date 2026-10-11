use super::*;
use crate::{AuthResponse, FieldMap, FieldValue};

#[expect(
    clippy::panic_in_result_fn,
    reason = "The contract compares native property order and complete HTTP bytes"
)]
fn observe(error: AuthError, status: u16, keys: &[&str], bytes: &[u8]) -> AuthResult<FieldValue> {
    assert_eq!(error.status_code(), status);
    assert!(error.is_api_error());
    let response = error.to_auth_response();
    let body = response.body.field_value()?;
    let fields = body
        .as_object()
        .map(|body| body.snapshot_fields())
        .transpose()?;
    assert_eq!(
        fields
            .as_ref()
            .map(|fields| fields.keys().map(String::as_str).collect::<Vec<_>>())
            .unwrap_or_default(),
        keys
    );
    let response = response.into_http_response()?;
    assert_eq!(response.status, status);
    assert_eq!(response.body.bytes()?.as_ref(), bytes);
    Ok(body)
}

#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "The same message must have different bodies for coded and explicit errors"
)]
fn coded_errors_and_explicit_message_bodies_have_distinct_contracts() -> AuthResult<()> {
    let coded = observe(
        AuthError::from_code(400, "USER_NOT_FOUND", "User not found"),
        400,
        &["message", "code"],
        br#"{"message":"User not found","code":"USER_NOT_FOUND"}"#,
    )?;
    assert_eq!(
        coded,
        FieldValue::from(FieldMap::from([
            ("message".into(), "User not found".into()),
            ("code".into(), "USER_NOT_FOUND".into()),
        ]))
    );
    let explicit: FieldValue = FieldMap::from([("message".into(), "User not found".into())]).into();
    let observed = observe(
        AuthResponse::native(Some(400), explicit.clone()).into(),
        400,
        &["message"],
        br#"{"message":"User not found"}"#,
    )?;
    assert!(observed.strict_equals(&explicit));
    Ok(())
}

#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "Explicit bodies retain identity, property presence, and mutations before HTTP serialization"
)]
fn explicit_error_body_retains_order_extra_properties_and_identity() -> AuthResult<()> {
    let body: FieldValue = FieldMap::from([
        ("code".into(), "CUSTOM".into()),
        ("message".into(), "initial".into()),
        (
            "details".into(),
            FieldMap::from([("reason".into(), "retained".into())]).into(),
        ),
        ("omitted".into(), FieldValue::Undefined),
    ])
    .into();
    let error = AuthError::from(AuthResponse::native(Some(409), body.clone()));
    let object = body
        .as_object()
        .ok_or_else(|| AuthError::internal("Expected explicit error object"))?;
    let _ = object.set("message", "User not found".into())?;
    let observed = observe(
        error,
        409,
        &["code", "message", "details", "omitted"],
        br#"{"code":"CUSTOM","message":"User not found","details":{"reason":"retained"}}"#,
    )?;
    assert!(observed.strict_equals(&body));
    assert_eq!(object.get("omitted")?, Some(FieldValue::Undefined));
    Ok(())
}

#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "An absent body and an explicit null remain distinct for native and HTTP callers"
)]
fn absent_and_null_error_bodies_remain_distinct() -> AuthResult<()> {
    let absent = observe(
        AuthResponse::native(Some(401), FieldValue::Undefined).into(),
        401,
        &[],
        b"",
    )?;
    let null = observe(
        AuthResponse::native(Some(401), FieldValue::Null).into(),
        401,
        &[],
        b"null",
    )?;
    assert!(absent.is_undefined());
    assert!(null.is_null());
    Ok(())
}
