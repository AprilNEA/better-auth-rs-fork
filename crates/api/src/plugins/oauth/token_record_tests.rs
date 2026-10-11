use super::*;
use better_auth_core::FieldDate;

#[test]
fn token_record_preserves_presence_order_and_slot_mutation() {
    let mut tokens = OAuthTokenSet::from_fields(FieldMap::from([
        ("extension".into(), 7.0.into()),
        ("idToken".into(), FieldValue::Undefined),
        ("accessToken".into(), FieldValue::Null),
        ("scopes".into(), vec!["openid".into()].into()),
    ]));
    assert!(!tokens.additional_fields.contains_key("accessToken"));
    assert!(!tokens.additional_fields.contains_key("idToken"));
    assert!(tokens.refresh_token.is_undefined());
    assert!(matches!(
        tokens.id_token,
        SchemaValue::Dynamic(FieldValue::Undefined)
    ));
    assert!(tokens.access_token.field_value().is_null());
    let fields = tokens.fields();
    assert_eq!(
        fields.keys().map(String::as_str).collect::<Vec<_>>(),
        ["extension", "idToken", "accessToken", "scopes"]
    );
    assert!(fields.get("idToken").is_some_and(FieldValue::is_undefined));
    tokens.access_token = Some("replacement".to_owned()).into();
    tokens.id_token = SchemaValue::Undefined;
    tokens.field_order.push("refreshToken".into());
    let fields = tokens.fields();
    assert_eq!(fields.get("accessToken"), Some(&"replacement".into()));
    assert!(!fields.contains_key("idToken"));
    assert!(!fields.contains_key("refreshToken"));
    assert_eq!(fields.get("extension"), Some(&7.0.into()));
}

#[test]
fn native_token_handles_survive_request_conversion() {
    let object: FieldValue = FieldMap::from([("claim".into(), true.into())]).into();
    let array: FieldValue = vec!["openid".into(), FieldValue::Null, 3.0.into()].into();
    let date: FieldValue = FieldDate::from_milliseconds(1_700_000_000_000.0).into();
    let fields = FieldMap::from([
        ("accessToken".into(), object.clone()),
        ("refreshToken".into(), 42.0.into()),
        ("accessTokenExpiresAt".into(), date.clone()),
        ("scopes".into(), array.clone()),
        ("raw".into(), object.clone()),
        ("custom".into(), array.clone()),
    ]);
    let tokens = OAuthTokenSet::from_fields(fields);
    let request = OAuthUserInfoRequest::from(tokens.clone());
    for actual in [tokens.fields(), request.fields()] {
        for (name, expected) in [
            ("accessToken", &object),
            ("raw", &object),
            ("scopes", &array),
            ("custom", &array),
            ("accessTokenExpiresAt", &date),
        ] {
            assert!(
                actual
                    .get(name)
                    .is_some_and(|value| value.strict_equals(expected)),
                "{name}"
            );
        }
        assert_eq!(actual.get("refreshToken"), Some(&42.0.into()));
    }
}

#[test]
fn scope_consumers_apply_join_and_trim_at_their_own_boundaries() -> AuthResult<()> {
    let scopes = SchemaValue::Dynamic(vec![" openid ".into(), FieldValue::Null, 7.0.into()].into());
    assert_eq!(
        joined_scopes(&scopes)?.display_utf16()?,
        " openid ,,7".into()
    );
    assert!(merge_scopes(&"email".into(), &scopes).is_err());
    let scopes =
        SchemaValue::Dynamic(vec![" openid ".into(), "email".into(), "profile".into()].into());
    assert_eq!(
        merge_scopes(&"email, openid".into(), &scopes)?.display_utf16()?,
        "email,openid,profile".into()
    );
    assert!(joined_scopes(&SchemaValue::Dynamic(7.0.into())).is_err());
    assert!(joined_scopes(&SchemaValue::Dynamic(FieldValue::Null))?.is_undefined());
    Ok(())
}

#[test]
fn callback_metadata_preserves_real_presence_order_and_extension_fields() -> AuthResult<()> {
    let tokens = OAuthTokenSet::from_fields(FieldMap::from([
        ("accessToken".into(), "access".into()),
        ("user".into(), "overridden".into()),
    ]));
    let request = crate::plugins::oauth::handlers::callback_user_request(&tokens, None, None)?;
    assert!(request.user.field_value().is_undefined());
    assert!(request.fields().contains_key("user"));
    assert!(!request.fields().contains_key("expectedIdTokenNonce"));
    for input in [Some("null"), Some("invalid JSON")] {
        let request = crate::plugins::oauth::handlers::callback_user_request(&tokens, input, None)?;
        assert!(
            request
                .fields()
                .get("user")
                .is_some_and(FieldValue::is_undefined)
        );
    }
    let tokens =
        OAuthTokenSet::from_fields(FieldMap::from([("accessToken".into(), "access".into())]));
    let request = crate::plugins::oauth::handlers::callback_user_request(
        &tokens,
        Some(r#"{"name":{"firstName":"Ada"},"custom":{"retained":true}}"#),
        Some("nonce"),
    )?;
    let fields = request.fields();
    assert_eq!(
        fields.keys().map(String::as_str).collect::<Vec<_>>(),
        ["accessToken", "expectedIdTokenNonce", "user"]
    );
    assert!(
        request
            .user
            .field_value()
            .model_property("custom")?
            .model_property("retained")?
            .is_truthy()
    );
    assert!(
        fields
            .get("user")
            .is_some_and(|value| value.strict_equals(&request.user.field_value()))
    );
    let existing = OAuthTokenSet::from_fields(FieldMap::from([
        ("user".into(), "old user".into()),
        ("custom".into(), true.into()),
        ("expectedIdTokenNonce".into(), "old nonce".into()),
    ]));
    let request = crate::plugins::oauth::handlers::callback_user_request(
        &existing,
        Some("false"),
        Some("new nonce"),
    )?;
    assert_eq!(
        request
            .fields()
            .keys()
            .map(String::as_str)
            .collect::<Vec<_>>(),
        ["user", "custom", "expectedIdTokenNonce"]
    );
    assert_eq!(request.user.field_value(), false.into());
    assert_eq!(
        request.expected_id_token_nonce.field_value(),
        "new nonce".into()
    );
    Ok(())
}
