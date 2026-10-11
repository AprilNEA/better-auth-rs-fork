use super::*;
use better_auth::__private_core::{
    ApiKey, ApiKeyView, AuthRecordFields, AuthSchema, AuthStore, DeviceCode, FromFieldMap, Jwk,
    TwoFactor, WalletAddress, store::schema::EntityRole,
};
use serde::{Serialize, de::DeserializeOwned};

pub(super) fn supports(role: EntityRole) -> bool {
    matches!(
        role,
        EntityRole::ApiKey
            | EntityRole::DeviceCode
            | EntityRole::TwoFactor
            | EntityRole::Jwk
            | EntityRole::WalletAddress
    )
}

fn exact(actual: &FieldMap, expected: &FieldMap) {
    assert_eq!(
        actual, expected,
        "Every typed value must match the raw adapter result"
    );
    assert_eq!(
        actual.keys().collect::<Vec<_>>(),
        expected.keys().collect::<Vec<_>>(),
        "Typed fields must preserve own Undefined, omitted properties, and declaration order"
    );
    for (name, value) in expected {
        assert!(
            actual[name].strict_equals(value),
            "{name}: typed construction must retain object identity"
        );
    }
}

fn serialized<T: Serialize + DeserializeOwned>(record: &T, fields: &FieldMap) -> AuthResult<()> {
    let json = FieldValue::from(fields.clone())
        .stringify()?
        .expect("The record is a JSON object");
    assert_eq!(
        serde_json::to_string(record)?,
        json,
        "Complete typed JSON and key order"
    );
    let restored: T = serde_json::from_str(&json)?;
    assert_eq!(
        serde_json::to_string(&restored)?,
        json,
        "JSON reconstruction must retain property order"
    );
    Ok(())
}

pub(super) fn project(role: EntityRole, fields: FieldMap) -> AuthResult<FieldMap> {
    let output = match role {
        EntityRole::ApiKey => {
            let record = ApiKey::from_field_values(fields.clone())?;
            let output = record.field_values()?;
            serialized(&record, &fields)?;
            let public = ApiKeyView::try_from_api_key(&record)?;
            for name in ["metadata", "permissions"] {
                assert_eq!(
                    fields.get(name),
                    Some(&FieldValue::Null),
                    "These fixtures keep public metadata and permission parsing neutral"
                );
            }
            let mut expected = fields.clone();
            let _ = expected.remove("key");
            exact(&public.field_values()?, &expected);
            serialized(&public, &expected)?;
            output
        }
        EntityRole::TwoFactor => {
            let record = TwoFactor::from_field_values(fields.clone())?;
            serialized(&record, &fields)?;
            record.field_values()?
        }
        EntityRole::DeviceCode => {
            let record = DeviceCode::from(fields.clone());
            assert!(
                record.consumption_bindings().is_err(),
                "Plain FieldMap input cannot supply adapter consumption bindings"
            );
            serialized(&record, &fields)?;
            record.field_values()?
        }
        EntityRole::Jwk => Jwk::from_field_values(fields.clone())?.field_values()?,
        EntityRole::WalletAddress => {
            let record = WalletAddress::from_field_values(fields.clone())?;
            serialized(&record, &fields)?;
            record.field_values()?
        }
        _ => return Err(AuthError::internal("Unsupported typed replacement model")),
    };
    exact(&output, &fields);
    Ok(output)
}

pub(super) async fn read<S: AuthSchema>(
    store: &dyn AuthStore<S>,
    target: &Target,
    id: FieldValue,
) -> AuthResult<Option<FieldMap>> {
    match target.role {
        EntityRole::ApiKey => store
            .get_api_key_by_id_value(&id.decode()?)
            .await?
            .map(|row| row.field_values())
            .transpose(),
        EntityRole::TwoFactor => store
            .get_two_factor_by_user_id(OWNER)
            .await?
            .map(|row| row.field_values())
            .transpose(),
        EntityRole::DeviceCode => {
            let Some(row) = store
                .get_device_code_by_device_code("ordinary-native-device")
                .await?
            else {
                return Ok(None);
            };
            assert!(row.consumption_bindings()?.1);
            let cloned = row.structured_clone(
                &mut better_auth::__private_core::StructuredCloneContext::new(),
            )?;
            assert!(
                cloned.consumption_bindings()?.1,
                "Structured clone must retain sealed adapter bindings"
            );
            let restored: DeviceCode = serde_json::from_str(&serde_json::to_string(&row)?)?;
            assert!(
                restored.consumption_bindings().is_err(),
                "JSON cannot restore adapter consumption bindings"
            );
            Ok(Some(row.field_values()?))
        }
        EntityRole::Jwk => store
            .get_jwk(&id.decode::<String>()?)
            .await?
            .map(|row| row.field_values())
            .transpose(),
        EntityRole::WalletAddress => store
            .get_wallet_address("0x0000000000000000000000000000000000000001", None)
            .await?
            .map(|row| row.field_values())
            .transpose(),
        _ => Err(AuthError::internal("Unsupported typed replacement lookup")),
    }
}
