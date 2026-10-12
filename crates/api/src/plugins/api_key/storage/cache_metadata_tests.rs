use super::*;
use better_auth_core::{ApiKeyView, AuthRecordFields, FieldDate, FromFieldMap};

#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "The cache contract compares complete records, property order, and object identities across the JSON boundary."
)]
fn cache_preserves_declared_order_and_drops_undefined_only_at_json_serialization() -> AuthResult<()>
{
    let object = FieldValue::from(FieldMap::from([("source".into(), "output".into())]));
    let date = FieldDate::from_milliseconds(0.0);
    let fields = FieldMap::from([
        ("requestCount".into(), object.clone()),
        ("enabled".into(), FieldValue::Undefined),
        ("metadata".into(), object.clone()),
        ("id".into(), "metadata-key".into()),
        ("key".into(), "private-hash".into()),
        ("createdAt".into(), date.clone().into()),
        ("updatedAt".into(), date.into()),
    ]);
    let key = ApiKey::from_field_values(fields.clone())?;
    assert_eq!(key.field_values()?, fields);
    assert_eq!(
        key.field_values()?
            .keys()
            .map(String::as_str)
            .collect::<Vec<_>>(),
        [
            "requestCount",
            "enabled",
            "metadata",
            "id",
            "key",
            "createdAt",
            "updatedAt"
        ]
    );
    assert!(key.request_count.field_value().strict_equals(&object));
    assert!(key.metadata.field_value().strict_equals(&object));
    assert!(key.request_count.typed().is_err());

    let encoded = serialize(&key)?;
    let expected = r#"{"requestCount":{"source":"output"},"metadata":{"source":"output"},"id":"metadata-key","key":"private-hash","createdAt":"1970-01-01T00:00:00.000Z","updatedAt":"1970-01-01T00:00:00.000Z","expiresAt":null,"lastRefillAt":null,"lastRequest":null}"#;
    assert_eq!(encoded, FieldValue::from(expected));
    let restored = deserialize(Some(encoded.clone()))
        .ok_or_else(|| AuthError::internal("Expected the API key cache record"))?;
    let restored_fields = restored.field_values()?;
    assert_eq!(
        restored_fields
            .keys()
            .map(String::as_str)
            .collect::<Vec<_>>(),
        [
            "requestCount",
            "metadata",
            "id",
            "key",
            "createdAt",
            "updatedAt",
            "expiresAt",
            "lastRefillAt",
            "lastRequest"
        ]
    );
    assert!(!restored_fields.contains_key("enabled"));
    assert!(!restored_fields.contains_key("name"));
    assert!(!restored.request_count.field_value().strict_equals(&object));
    assert!(!restored.metadata.field_value().strict_equals(&object));
    assert!(
        !restored
            .request_count
            .field_value()
            .strict_equals(&restored.metadata.field_value())
    );
    assert_eq!(restored.created_at.typed()?.milliseconds(), 0.0);
    assert_eq!(restored.updated_at.typed()?.milliseconds(), 0.0);
    assert_eq!(serialize(&restored)?, FieldValue::from(expected));

    let public = ApiKeyView::try_from_api_key(&restored)?;
    assert_eq!(
        public
            .field_values()?
            .keys()
            .map(String::as_str)
            .collect::<Vec<_>>(),
        [
            "requestCount",
            "metadata",
            "id",
            "createdAt",
            "updatedAt",
            "expiresAt",
            "lastRefillAt",
            "lastRequest",
            "permissions"
        ]
    );
    assert_eq!(
        serde_json::to_string(&public)?,
        r#"{"requestCount":{"source":"output"},"metadata":{"source":"output"},"id":"metadata-key","createdAt":"1970-01-01T00:00:00.000Z","updatedAt":"1970-01-01T00:00:00.000Z","expiresAt":null,"lastRefillAt":null,"lastRequest":null,"permissions":null}"#
    );
    assert!(
        public
            .request_count
            .field_value()
            .strict_equals(&restored.request_count.field_value())
    );
    assert!(
        public
            .metadata
            .strict_equals(&restored.metadata.field_value())
    );
    Ok(())
}
