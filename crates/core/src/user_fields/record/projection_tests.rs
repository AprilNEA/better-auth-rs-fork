use super::*;
use crate::{
    FieldFunction,
    plugin_runtime::ModelFields,
    store::schema::EntityRole,
    user_fields::{FieldTransforms, UserFieldTransform},
};
use std::sync::atomic::{AtomicUsize, Ordering};

async fn project(
    method: usize,
    fields: &UserConfig,
    storage: &FieldMap,
) -> AuthResult<Vec<FieldMap>> {
    match method {
        0 => Ok(vec![fields.project_record(storage, false, true).await?]),
        1 => {
            fields
                .project_records(std::slice::from_ref(storage), false, true)
                .await
        }
        2 => {
            fields
                .project_records_then(std::slice::from_ref(storage), false, true, |index, row| {
                    assert_eq!(index, 0);
                    std::future::ready(Ok(row))
                })
                .await
        }
        _ => {
            fields
                .project_records_batches_then(std::slice::from_ref(storage), false, true, |rows| {
                    assert_eq!(rows.len(), 1);
                    assert_eq!(rows.first().map(|(index, _)| *index), Some(0));
                    std::future::ready(Ok(rows))
                })
                .await
        }
    }
}

#[tokio::test]
async fn raw_helpers_share_native_replacements_and_defer_dynamic_ids() -> AuthResult<()> {
    for (role, keys) in [
        (
            EntityRole::ApiKey,
            &[
                "configId",
                "name",
                "start",
                "referenceId",
                "prefix",
                "key",
                "refillInterval",
                "refillAmount",
                "lastRefillAt",
                "enabled",
                "rateLimitEnabled",
                "rateLimitTimeWindow",
                "rateLimitMax",
                "requestCount",
                "remaining",
                "lastRequest",
                "expiresAt",
                "createdAt",
                "updatedAt",
                "permissions",
                "metadata",
                "id",
            ][..],
        ),
        (
            EntityRole::Passkey,
            &[
                "name",
                "publicKey",
                "userId",
                "credentialID",
                "counter",
                "deviceType",
                "backedUp",
                "transports",
                "createdAt",
                "aaguid",
                "id",
            ][..],
        ),
    ] {
        for method in 0..4 {
            let id = FieldObject::from(FieldMap::from([(
                "toString".into(),
                FieldFunction::contextual(|_, _| {
                    Err(crate::AuthError::config("ID read too early"))
                })
                .into(),
            )]));
            let payload: Value = FieldMap::from([("answer".into(), 7.into())]).into();
            let calls = Arc::new(AtomicUsize::new(0));
            let callback_payload = payload.clone();
            let callback_id = id.clone();
            let callback_calls = calls.clone();
            let replacement = UserFieldConfig {
                field_type: UserFieldType::Json,
                field_name: Some("physicalName".into()),
                returned: Some(false),
                transform: Some(FieldTransforms {
                    output: Some(UserFieldTransform::new(move |value| {
                        assert!(value.strict_equals(&callback_payload));
                        let _ = callback_calls.fetch_add(1, Ordering::SeqCst);
                        let _ = callback_id.set(
                            "toString",
                            FieldFunction::contextual(|_, _| Ok("after-name".into())).into(),
                        )?;
                        Ok(vec![value].into())
                    })),
                    ..Default::default()
                }),
                ..Default::default()
            };
            let mut fields = ModelFields::plugin_native_fields(role);
            let _ = fields.fields_mut().insert("name".into(), replacement);
            let storage = FieldMap::from([
                ("id".into(), Value::Object(id)),
                ("physicalName".into(), payload.clone()),
                ("unmapped".into(), true.into()),
            ]);
            let actual = project(method, &fields, &storage).await?;
            let mut expected: FieldMap = keys
                .iter()
                .map(|name| ((*name).into(), Value::Undefined))
                .collect();
            let _ = expected.insert("name".into(), vec![payload.clone()].into());
            let _ = expected.insert("id".into(), "after-name".into());
            if role == EntityRole::ApiKey {
                let _ = expected.insert("metadata".into(), Value::Null);
            }
            assert_eq!(actual, [expected]);
            assert_eq!(
                actual
                    .first()
                    .map(|row| row.keys().map(String::as_str).collect::<Vec<_>>()),
                Some(keys.to_vec()),
            );
            assert_eq!(calls.load(Ordering::SeqCst), 1);
            assert!(
                storage
                    .get("physicalName")
                    .is_some_and(|value| value.strict_equals(&payload))
            );
            assert_eq!(storage.get("unmapped"), Some(&true.into()));
        }
    }
    Ok(())
}

#[tokio::test]
async fn raw_helpers_convert_ids_at_the_declared_slot_and_keep_nullish_presence() -> AuthResult<()>
{
    for method in 0..4 {
        for id_first in [false, true] {
            let fields = UserConfig {
                additional_fields: Some(
                    if id_first {
                        ["id", "first"]
                    } else {
                        ["first", "id"]
                    }
                    .into_iter()
                    .map(|name| {
                        (
                            name.into(),
                            UserFieldConfig {
                                field_name: (name == "id").then(|| "ignoredId".into()),
                                transform: Some(FieldTransforms {
                                    output: Some(UserFieldTransform::new(move |_| {
                                        Err(crate::AuthError::config(if name == "id" {
                                            "Application ID transform ran"
                                        } else {
                                            "field-error"
                                        }))
                                    })),
                                    ..Default::default()
                                }),
                                ..Default::default()
                            },
                        )
                    })
                    .collect(),
                ),
            };
            let id: Value = FieldMap::from([(
                "toString".into(),
                FieldFunction::contextual(|_, _| Err(crate::AuthError::config("id-error"))).into(),
            )])
            .into();
            let storage = FieldMap::from([("id".into(), id), ("first".into(), true.into())]);
            let error = project(method, &fields, &storage).await;
            assert!(
                matches!(error, Err(crate::AuthError::Config(message)) if message == if id_first { "id-error" } else { "field-error" })
            );
        }
        for (raw, expected) in [
            (None, Value::Undefined),
            (Some(Value::Undefined), Value::Undefined),
            (Some(Value::Null), Value::Null),
            (
                Some(vec![Value::from(4), Value::Null, Value::from(false)].into()),
                "4,,false".into(),
            ),
        ] {
            let storage = raw.into_iter().map(|value| ("id".into(), value)).collect();
            let actual = project(method, &UserConfig::default(), &storage).await?;
            assert_eq!(actual, [FieldMap::from([("id".into(), expected)])]);
        }
    }
    Ok(())
}

#[tokio::test]
async fn extracted_core_projection_keeps_its_logical_values_and_storage_priority() -> AuthResult<()>
{
    let extra: Value = FieldMap::from([("scope".into(), "retained".into())]).into();
    let core = FieldMap::from([
        ("id".into(), Value::from(42)),
        ("extra".into(), extra.clone()),
        ("name".into(), "core-name".into()),
    ]);
    let fields = UserConfig {
        additional_fields: Some(
            [(
                "name".into(),
                UserFieldConfig {
                    field_name: Some("physicalName".into()),
                    ..Default::default()
                },
            )]
            .into(),
        ),
    };
    let storage = FieldMap::from([
        ("id".into(), "storage-id".into()),
        ("physicalName".into(), "storage-name".into()),
        ("extra".into(), "storage-extra".into()),
    ]);
    let actual = fields
        .record_output_fields(core, &storage, true, true)
        .await?;
    assert_eq!(
        actual,
        FieldMap::from([
            ("id".into(), Value::from(42)),
            ("extra".into(), extra.clone()),
            ("name".into(), "storage-name".into()),
        ])
    );
    assert!(
        actual
            .get("extra")
            .is_some_and(|value| value.strict_equals(&extra))
    );
    assert_eq!(
        actual.keys().map(String::as_str).collect::<Vec<_>>(),
        ["id", "extra", "name"]
    );
    Ok(())
}
