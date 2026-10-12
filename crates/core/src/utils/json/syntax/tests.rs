#![expect(
    clippy::panic_in_result_fn,
    reason = "The parser regressions assert diagnostic precedence, native properties, and original error identity."
)]

use crate::utils::json::parse_native_json;
use crate::{AuthError, AuthResult, FieldFunction, FieldMap, FieldValue, Utf16String};

fn assert_syntax_error(source: FieldValue, message: Utf16String) -> AuthResult<()> {
    let error = parse_native_json(&source)
        .err()
        .ok_or_else(|| AuthError::internal("Invalid JSON unexpectedly parsed"))?;
    let thrown = error.into_thrown_value()?;
    let message = Utf16String::from_units(
        "JSON Parse error: "
            .encode_utf16()
            .chain(message.as_utf16().iter().copied())
            .collect(),
    );
    assert_eq!(thrown.model_property("name")?, "SyntaxError".into());
    assert_eq!(thrown.model_property("message")?, message.clone().into());
    assert_eq!(
        thrown.display_utf16()?,
        Utf16String::from_units(
            "SyntaxError: "
                .encode_utf16()
                .chain(message.as_utf16().iter().copied())
                .collect()
        )
    );
    let object = thrown
        .as_object()
        .ok_or_else(|| AuthError::internal("SyntaxError object is absent"))?;
    assert_eq!(object.own_keys()?, ["message"]);
    assert!(object.enumerable_keys()?.is_empty());
    assert!(object.own_property_descriptor("name")?.is_none());
    assert!(
        object
            .own_property_descriptor("message")?
            .is_some_and(|descriptor| !descriptor.enumerable)
    );
    Ok(())
}

#[test]
fn grammar_diagnostics_follow_nested_value_and_property_states() -> AuthResult<()> {
    for (source, message) in [
        ("", "Unexpected EOF"),
        ("{", "Expected '}'"),
        ("{foo", "Expected '}'"),
        (
            r#"{"a""#,
            "Expected ':' before value in object property definition",
        ),
        (r#"{"a":"#, "Unexpected EOF"),
        (r#"{"a":1,foo}"#, "Property name must be a string literal"),
        (r#"{"a":[1 2]}"#, "Expected ']'"),
        (r#"[{"a":1 2}]"#, "Expected '}'"),
        (
            r#"[[{"a":[1,]}]]"#,
            "Unexpected comma at the end of array expression",
        ),
        ("[1,}", "Unexpected token '}'"),
        ("[]{}", "Unable to parse JSON string"),
        ("truefal@", "Unable to parse JSON string"),
        ("1e+", "Unable to parse JSON string"),
        ("[1e+]", "Expected ']'"),
        ("_name$42", "Unexpected identifier \"_name$42\""),
        ("a\u{200c}b", "Unexpected identifier \"a\u{200c}b\""),
    ] {
        assert_syntax_error(source.into(), message.into())?;
    }
    assert_syntax_error(
        "a".repeat(201).into(),
        format!("Unexpected identifier \"{}...\"", "a".repeat(200)).into(),
    )
}

#[test]
fn lexical_errors_override_pending_delimiter_and_root_errors() -> AuthResult<()> {
    for (source, message) in [
        (r#"{"a" @}"#, "Unrecognized token '@'"),
        (r#"{"a":1 @}"#, "Unrecognized token '@'"),
        ("{}@", "Unrecognized token '@'"),
        ("[1,1.]", "Invalid digits after decimal point"),
        ("-", "Invalid number"),
        ("'text'", "Single quotes (') are not allowed in JSON"),
        (r#""ok" "\q""#, "Invalid escape character q"),
        (r#""\u0""#, "\\u must be followed by 4 hex digits"),
        (r#""\u000""#, "\"\\u000\"\" is not a valid unicode escape"),
        ("\"raw\ncontrol\"", "Unterminated string"),
    ] {
        assert_syntax_error(source.into(), message.into())?;
    }
    Ok(())
}

#[test]
fn syntax_diagnostics_retain_original_utf16_code_units() -> AuthResult<()> {
    for (source, prefix, suffix) in [
        (vec![0xd800], "Unrecognized token '", "'"),
        (vec![34, 92, 0xd800, 34], "Invalid escape character ", ""),
        (
            vec![34, 92, 117, 0xd800, 48, 48, 48, 34],
            "\"\\u",
            "000\" is not a valid unicode escape",
        ),
    ] {
        assert_syntax_error(
            Utf16String::from_units(source).into(),
            Utf16String::from_units(
                prefix
                    .encode_utf16()
                    .chain([0xd800])
                    .chain(suffix.encode_utf16())
                    .collect(),
            ),
        )?;
    }
    Ok(())
}

#[test]
fn valid_source_representation_errors_keep_their_original_category() -> AuthResult<()> {
    let text = r#"{"\ud800":"value"}"#;
    assert_eq!(
        super::check(&text.encode_utf16().collect::<Vec<_>>()),
        Ok(())
    );
    let error = parse_native_json(&text.into()).err().ok_or_else(|| {
        AuthError::internal("FieldMap unexpectedly accepted an unpaired surrogate key")
    })?;
    assert!(matches!(error, AuthError::Serialization(_)));
    assert_eq!(
        error.into_thrown_value()?.model_property("name")?,
        "Error".into()
    );

    let text = format!(
        "{}{{\"x\":[1e400,\"\\ud800\",null,true,false]}}{}",
        "[".repeat(256),
        "]".repeat(256)
    );
    assert_eq!(
        super::check(&text.encode_utf16().collect::<Vec<_>>()),
        Ok(())
    );
    Ok(())
}

#[test]
fn source_conversion_failure_keeps_the_original_thrown_value() -> AuthResult<()> {
    let original: FieldValue = FieldMap::from([("failure".into(), "toString".into())]).into();
    let thrown = original.clone();
    let source = FieldMap::from([(
        "toString".into(),
        FieldFunction::contextual(move |_, _| Err(AuthError::from_thrown(thrown.clone()))).into(),
    )])
    .into();
    let error = parse_native_json(&source)
        .err()
        .ok_or_else(|| AuthError::internal("JSON source conversion unexpectedly succeeded"))?;
    assert!(error.into_thrown_value()?.strict_equals(&original));
    Ok(())
}
