//! Generic Serde adapters for field values and record projections.
//!
//! Serde value adapters cannot access an enclosing property key or omit a key already emitted by
//! their parent. Use `FieldValue::json` or `FieldValue::stringify` for native JSON semantics.
//! Generic Serde errors retain text; native JSON entry points retain the original `AuthError`.

#[cfg(test)]
#[path = "serde_tests.rs"]
mod live_tests;

pub(crate) use super::json::Json;
use crate::{FieldDate, FieldMap, FieldValue};
use ::serde::{Deserialize, Serialize, de::Error};

pub mod map {
    use super::*;

    pub fn serialize<S: ::serde::Serializer>(
        fields: &FieldMap,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        super::super::json::serialize_fields(fields, serializer)
    }

    pub fn deserialize<'de, D: ::serde::Deserializer<'de>>(
        deserializer: D,
    ) -> Result<FieldMap, D::Error> {
        let value = ::serde_json::Map::<String, ::serde_json::Value>::deserialize(deserializer)?;
        FieldMap::from_json(value).map_err(D::Error::custom)
    }
}

pub mod value {
    use super::*;

    pub fn serialize<S: ::serde::Serializer>(
        value: &FieldValue,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        Json(value).serialize(serializer)
    }

    pub fn deserialize<'de, D: ::serde::Deserializer<'de>>(
        deserializer: D,
    ) -> Result<FieldValue, D::Error> {
        let value = ::serde_json::Value::deserialize(deserializer)?;
        FieldValue::from_json(value).map_err(D::Error::custom)
    }
}

pub mod optional_value {
    use super::*;

    /// Preserve an absent Rust option as null while omitting an explicit undefined or function.
    pub fn is_json_omitted(value: &Option<FieldValue>) -> bool {
        value.as_ref().is_some_and(FieldValue::is_json_omitted)
    }

    /// Omit an absent property and native values omitted by JSON object serialization.
    pub fn is_absent_or_json_omitted(value: &Option<FieldValue>) -> bool {
        value.as_ref().is_none_or(FieldValue::is_json_omitted)
    }

    pub fn serialize<S: ::serde::Serializer>(
        value: &Option<FieldValue>,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        match value {
            Some(value) => super::value::serialize(value, serializer),
            None => serializer.serialize_none(),
        }
    }

    pub fn deserialize<'de, D: ::serde::Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Option<FieldValue>, D::Error> {
        let value = super::value::deserialize(deserializer)?;
        Ok((!value.is_null()).then_some(value))
    }
}

pub(crate) fn revive_schema_date(value: &mut FieldValue) {
    if let FieldValue::String(text) = value
        && let Some(date) = crate::utils::json::parse_json_date(text)
    {
        *value = FieldDate::from(date).into();
    }
}

pub mod schema_date {
    use super::*;

    pub fn serialize<S: ::serde::Serializer>(
        value: &crate::SchemaValue<FieldDate>,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        super::value::serialize(&value.field_value(), serializer)
    }

    pub fn deserialize<'de, D: ::serde::Deserializer<'de>>(
        deserializer: D,
    ) -> Result<crate::SchemaValue<FieldDate>, D::Error> {
        let mut value = super::value::deserialize(deserializer)?;
        revive_schema_date(&mut value);
        Ok(crate::SchemaValue::from_field(value))
    }
}

pub mod optional_schema_date {
    use super::*;

    pub fn serialize<S: ::serde::Serializer>(
        value: &crate::SchemaValue<Option<FieldDate>>,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        super::value::serialize(&value.field_value(), serializer)
    }

    pub fn deserialize<'de, D: ::serde::Deserializer<'de>>(
        deserializer: D,
    ) -> Result<crate::SchemaValue<Option<FieldDate>>, D::Error> {
        let value = schema_date::deserialize(deserializer)?.into_field_value();
        Ok(crate::SchemaValue::from_field(value))
    }
}

pub mod date {
    use super::*;

    pub fn serialize<S: ::serde::Serializer>(
        value: &FieldDate,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        super::value::serialize(&FieldValue::Date(value.clone()), serializer)
    }

    pub fn deserialize<'de, D: ::serde::Deserializer<'de>>(
        deserializer: D,
    ) -> Result<FieldDate, D::Error> {
        let value = String::deserialize(deserializer)?;
        Ok(crate::utils::date::parse_date_constructor(&value).unwrap_or_else(FieldDate::invalid))
    }
}

pub mod optional_date {
    use super::*;

    pub fn serialize<S: ::serde::Serializer>(
        value: &Option<FieldDate>,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        match value {
            Some(value) => super::date::serialize(value, serializer),
            None => serializer.serialize_none(),
        }
    }

    pub fn deserialize<'de, D: ::serde::Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Option<FieldDate>, D::Error> {
        Ok(Option::<String>::deserialize(deserializer)?.map(|value| {
            crate::utils::date::parse_date_constructor(&value).unwrap_or_else(FieldDate::invalid)
        }))
    }
}

pub mod date_update {
    use super::*;

    pub fn serialize<S: ::serde::Serializer>(
        value: &Option<Option<FieldDate>>,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        match value {
            Some(value) => optional_date::serialize(value, serializer),
            None => serializer.serialize_none(),
        }
    }

    pub fn deserialize<'de, D: ::serde::Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Option<Option<FieldDate>>, D::Error> {
        optional_date::deserialize(deserializer).map(Some)
    }
}

#[cfg(test)]
#[expect(
    clippy::panic_in_result_fn,
    reason = "Regression assertions verify public DTO date decoding and JSON preservation"
)]
mod tests {
    use crate::{
        ApiKey, AuthRecordFields, AuthResult, FieldDate, FieldMap, FieldValue, FromFieldMap,
        Invitation, InvitationView, Member, Organization, OrganizationRole, Passkey, Team,
        TeamMember,
        wire::{ApiKeyView, PasskeyView},
    };
    use ::serde::{Serialize, de::DeserializeOwned};
    use serde_json::{Value, json};

    fn assert_raw_date_strings<T: DeserializeOwned + Serialize>(fields: &[&str]) -> AuthResult<()> {
        // Upstream safeJSONParse retains strings outside its valid UTC ISO date grammar.
        for text in [
            "hello",
            "2100-01-01T00:00Z",
            "2100-01-01T00:00:00+00:00",
            "2100-13-01T00:00:00Z",
        ] {
            let input = Value::Object(
                fields
                    .iter()
                    .map(|field| ((*field).into(), text.into()))
                    .collect(),
            );
            let decoded: T = serde_json::from_value(input.clone())?;
            assert_eq!(serde_json::to_value(decoded)?, input);
        }
        Ok(())
    }

    #[test]
    fn api_key_and_passkey_date_strings_survive_public_serde() -> AuthResult<()> {
        let fields = [
            "createdAt",
            "updatedAt",
            "expiresAt",
            "lastRefillAt",
            "lastRequest",
        ];
        assert_raw_date_strings::<ApiKey>(&fields)?;
        assert_raw_date_strings::<ApiKeyView>(&fields)?;
        assert_raw_date_strings::<Passkey>(&["createdAt", "updatedAt"])?;
        assert_raw_date_strings::<PasskeyView>(&["createdAt"])?;
        Ok(())
    }

    #[test]
    fn api_key_and_passkey_iso_dates_keep_typed_access() -> AuthResult<()> {
        let text = "2100-01-01T00:00:00.000Z";
        let input = json!({
            "createdAt": text,
            "updatedAt": text,
            "expiresAt": text,
            "lastRefillAt": text,
            "lastRequest": text,
        });
        let key: ApiKey = serde_json::from_value(input.clone())?;
        let key_view: ApiKeyView = serde_json::from_value(input.clone())?;
        let passkey_input = json!({"createdAt": text, "updatedAt": text});
        let passkey: Passkey = serde_json::from_value(passkey_input.clone())?;
        let passkey_view_input = json!({"createdAt": text});
        let passkey_view: PasskeyView = serde_json::from_value(passkey_view_input.clone())?;
        let expected = FieldDate::from_milliseconds(4_102_444_800_000.0);
        for date in [
            &key.created_at,
            &key.updated_at,
            &key_view.created_at,
            &key_view.updated_at,
            &passkey.updated_at,
        ] {
            assert_eq!(date.typed()?, &expected);
        }
        for date in [
            &key.expires_at,
            &key.last_refill_at,
            &key.last_request,
            &key_view.expires_at,
            &key_view.last_refill_at,
            &key_view.last_request,
            &passkey.created_at,
            &passkey_view.created_at,
        ] {
            assert_eq!(date.typed()?, &Some(expected.clone()));
        }
        assert_eq!(serde_json::to_value(key)?, input);
        assert_eq!(serde_json::to_value(key_view)?, input);
        assert_eq!(serde_json::to_value(passkey)?, passkey_input);
        assert_eq!(serde_json::to_value(passkey_view)?, passkey_view_input);
        Ok(())
    }

    fn check_organization_json<T>(dates: &[&str]) -> AuthResult<T>
    where
        T: DeserializeOwned + Serialize + AuthRecordFields + FromFieldMap,
    {
        let source = r#"{"role":{"dynamic":true},"2":"two","updatedAt":"2100-01-01T00:00:00.000Z","id":null,"1":"one","extra":{"when":"2100-01-01T00:00:00.000Z"},"createdAt":"2100-01-01T00:00:00.000Z","expiresAt":"2100-01-01T00:00:00.000Z","01":false}"#;
        let source_fields = FieldMap::from_json(serde_json::from_str(source)?)?;
        let native = T::from_field_values(source_fields.clone())?.field_values()?;
        assert_eq!(native, source_fields);
        assert_eq!(
            native.keys().collect::<Vec<_>>(),
            source_fields.keys().collect::<Vec<_>>()
        );

        let record: T = serde_json::from_str(source)?;
        let mut expected = source_fields;
        for name in dates {
            let _ = expected.insert(
                (*name).into(),
                FieldDate::from_milliseconds(4_102_444_800_000.0).into(),
            );
        }
        let actual = record.field_values()?;
        assert_eq!(actual, expected);
        assert_eq!(
            actual.keys().map(String::as_str).collect::<Vec<_>>(),
            [
                "1",
                "2",
                "role",
                "updatedAt",
                "id",
                "extra",
                "createdAt",
                "expiresAt",
                "01"
            ]
        );
        assert_eq!(
            serde_json::to_string(&record)?,
            r#"{"1":"one","2":"two","role":{"dynamic":true},"updatedAt":"2100-01-01T00:00:00.000Z","id":null,"extra":{"when":"2100-01-01T00:00:00.000Z"},"createdAt":"2100-01-01T00:00:00.000Z","expiresAt":"2100-01-01T00:00:00.000Z","01":false}"#
        );
        let missing: T = serde_json::from_str("{}")?;
        assert!(missing.field_values()?.is_empty());
        assert_eq!(serde_json::to_string(&missing)?, "{}");
        for value in [
            Value::Null,
            json!(false),
            json!(42),
            json!({"dynamic": true}),
            json!(["2100-01-01T00:00:00.000Z"]),
            json!("raw-date"),
            json!("2100-01-01T00:00Z"),
            json!("2100-01-01T00:00:00+00:00"),
            json!("2100-13-01T00:00:00Z"),
        ] {
            let input: serde_json::Map<String, Value> = dates
                .iter()
                .map(|name| ((*name).into(), value.clone()))
                .collect();
            let decoded: T = serde_json::from_value(Value::Object(input.clone()))?;
            let fields = decoded.field_values()?;
            let expected = FieldMap::from_json(input.clone())?;
            assert_eq!(fields, expected);
            assert_eq!(
                fields.keys().collect::<Vec<_>>(),
                expected.keys().collect::<Vec<_>>()
            );
            assert_eq!(serde_json::to_value(&decoded)?, Value::Object(input));
        }
        Ok(record)
    }

    #[test]
    fn organization_json_preserves_order_presence_and_date_boundaries() -> AuthResult<()> {
        let organization = check_organization_json::<Organization>(&["createdAt"])?;
        let member = check_organization_json::<Member>(&["createdAt"])?;
        let invitation = check_organization_json::<Invitation>(&["expiresAt", "createdAt"])?;
        let view = check_organization_json::<InvitationView>(&["expiresAt", "createdAt"])?;
        let team = check_organization_json::<Team>(&["createdAt", "updatedAt"])?;
        let team_member = check_organization_json::<TeamMember>(&["createdAt"])?;
        let role = check_organization_json::<OrganizationRole>(&["createdAt", "updatedAt"])?;
        let expected = FieldDate::from_milliseconds(4_102_444_800_000.0);
        for date in [
            &organization.created_at,
            &member.created_at,
            &invitation.created_at,
            &invitation.expires_at,
            &view.created_at,
            &view.expires_at,
            &team.created_at,
            &team_member.created_at,
            &role.created_at,
        ] {
            assert_eq!(date.typed()?, &expected);
        }
        for date in [&team.updated_at, &role.updated_at] {
            assert_eq!(date.typed()?, &Some(expected.clone()));
        }
        let private: TeamMember =
            serde_json::from_str(r#"{"extra":false,"membershipKey":"private","createdAt":null}"#)?;
        let expected = FieldMap::from([
            ("extra".into(), false.into()),
            ("createdAt".into(), FieldValue::Null),
        ]);
        assert_eq!(private.field_values()?, expected);
        assert_eq!(
            private.field_order,
            expected.keys().cloned().collect::<Vec<_>>()
        );
        assert_eq!(
            serde_json::to_string(&private)?,
            r#"{"extra":false,"createdAt":null}"#
        );
        Ok(())
    }
}
