use super::member_contract_support::*;
use super::*;
use better_auth_core::{AuthRecordFields, Member, SchemaValue};
use better_auth_seaorm::sea_orm::{ConnectionTrait, DbBackend, Statement};

#[derive(Clone, Copy, Debug)]
enum Entry {
    Pair,
    NativePair,
    Id,
}

#[derive(Clone, Copy, Debug)]
enum Mode {
    Live,
    Object,
    Undefined,
    Null,
    Error,
    Missing,
}

fn declaration(fields: impl IntoIterator<Item = (&'static str, UserFieldConfig)>) -> UserConfig {
    UserConfig {
        additional_fields: Some(
            fields
                .into_iter()
                .map(|(name, field)| (name.into(), field))
                .collect(),
        ),
    }
}

async fn read<S: AuthSchema>(
    store: &dyn AuthStore<S>,
    entry: Entry,
    missing: bool,
) -> AuthResult<Option<Member>> {
    let user = if missing { "missing" } else { "user-b" };
    match entry {
        Entry::Pair => store.get_member("organization", user).await,
        Entry::NativePair => {
            store
                .get_member_value(&"organization".into(), &user.into())
                .await
        }
        Entry::Id => {
            store
                .get_member_by_id(if missing { "missing" } else { "member-b" })
                .await
        }
    }
}

async fn check<S: AuthSchema>(
    raw: Arc<dyn AuthStore<S>>,
    storage: Storage,
    entry: Entry,
    mode: Mode,
) -> AuthResult<()> {
    let _ = seed(raw.clone(), false, "user-a").await?;
    let writer = BetterAuth::new(config())
        .store_arc(raw.clone())
        .plugin(OrganizationPlugin::with_config(
            OrganizationConfig::default(),
        ))
        .plugin(Fields(vec![(
            EntityRole::Member,
            declaration([("createdAt", UserFieldConfig::default())]),
        )]))
        .build()
        .await?;
    match &storage {
        Storage::Memory(_) => {
            let mut target = member("member-b", "user-b", "member");
            target.created_at = SchemaValue::from_field("opaque-date".into());
            let _ = writer.store().insert_member(target).await?;
        }
        Storage::Sqlite(database) => {
            let _ = raw
                .insert_member(member("member-b", "user-b", "member"))
                .await?;
            let _ = database
                .execute_raw(Statement::from_string(
                    DbBackend::Sqlite,
                    "UPDATE member SET created_at = 'opaque-date' WHERE id = 'member-b'".to_owned(),
                ))
                .await
                .map_err(|error| AuthError::internal(error.to_string()))?;
        }
    }
    let before = storage.snapshot().await?;
    let events = Arc::new(Mutex::new(Vec::<FieldValue>::new()));
    let shared: FieldValue = FieldMap::from_iter([("native".into(), true.into())]).into();
    let fields = declaration([
        (
            "organizationId",
            UserFieldConfig {
                transform: Some(FieldTransforms {
                    output: Some(UserFieldTransform::new_async({
                        let events = events.clone();
                        let writer = writer.store().clone();
                        let storage = storage.clone();
                        move |value| {
                            let events = events.clone();
                            let writer = writer.clone();
                            let storage = storage.clone();
                            async move {
                                trace_lock(&events)?
                                    .push(vec!["organizationId".into(), value].into());
                                match storage {
                                    Storage::Memory(_) => {
                                        let _ = writer
                                            .update_member_role("member-b", "changed")
                                            .await?;
                                    }
                                    Storage::Sqlite(database) => {
                                        let _ = database.execute_raw(Statement::from_string(DbBackend::Sqlite,
                                    "UPDATE member SET role = 'changed' WHERE id = 'member-b'".to_owned()))
                                    .await.map_err(|error| AuthError::internal(error.to_string()))?;
                                    }
                                }
                                Ok(19.into())
                            }
                        }
                    })),
                    ..Default::default()
                }),
                ..Default::default()
            },
        ),
        (
            "role",
            UserFieldConfig {
                transform: Some(FieldTransforms {
                    output: Some(UserFieldTransform::new({
                        let events = events.clone();
                        let shared = shared.clone();
                        move |value| {
                            trace_lock(&events)?.push(vec!["role".into(), value.clone()].into());
                            match mode {
                                Mode::Object => Ok(shared.clone()),
                                Mode::Undefined => Ok(FieldValue::Undefined),
                                Mode::Null => Ok(FieldValue::Null),
                                Mode::Error => {
                                    Err(AuthError::Forbidden("member-output-original".into()))
                                }
                                Mode::Live | Mode::Missing => Ok(value),
                            }
                        }
                    })),
                    ..Default::default()
                }),
                ..Default::default()
            },
        ),
        (
            "createdAt",
            UserFieldConfig {
                transform: Some(FieldTransforms {
                    output: Some(UserFieldTransform::new({
                        let events = events.clone();
                        move |value| {
                            trace_lock(&events)?
                                .push(vec!["createdAt".into(), value.clone()].into());
                            Ok(value)
                        }
                    })),
                    ..Default::default()
                }),
                ..Default::default()
            },
        ),
        (
            "echo",
            UserFieldConfig {
                field_name: Some("role".into()),
                transform: Some(FieldTransforms {
                    output: Some(UserFieldTransform::new({
                        let events = events.clone();
                        move |value| {
                            trace_lock(&events)?.push(vec!["echo".into(), value.clone()].into());
                            Ok(value)
                        }
                    })),
                    ..Default::default()
                }),
                ..Default::default()
            },
        ),
    ]);
    let auth = BetterAuth::new(config())
        .store_arc(raw)
        .plugin(OrganizationPlugin::with_config(
            OrganizationConfig::default(),
        ))
        .plugin(Fields(vec![(
            EntityRole::Member,
            declaration([(
                "createdAt",
                UserFieldConfig {
                    field_type: UserFieldType::Date,
                    field_name: Some("role".into()),
                    returned: Some(false),
                    ..Default::default()
                },
            )]),
        )]))
        .plugin(Fields(vec![(EntityRole::Member, fields)]))
        .build()
        .await?;
    let result = read(auth.store().as_ref(), entry, matches!(mode, Mode::Missing)).await;
    let observed_role: FieldValue = if storage.memory() {
        "changed"
    } else {
        "member"
    }
    .into();
    let mut expected_events = Vec::new();
    let mut after = before.clone();
    if matches!(mode, Mode::Missing) {
        assert!(result?.is_none());
    } else {
        expected_events.extend([
            vec!["organizationId".into(), "organization".into()].into(),
            vec!["role".into(), observed_role.clone()].into(),
        ]);
        let target = after
            .get_mut("member")
            .and_then(|rows| {
                rows.iter_mut()
                    .find(|row| row.get("id").and_then(FieldValue::as_str) == Some("member-b"))
            })
            .ok_or_else(|| AuthError::internal("Expected target Member storage"))?;
        let _ = target.insert("role".into(), "changed".into());
        if matches!(mode, Mode::Error) {
            assert!(
                matches!(result, Err(AuthError::Forbidden(message)) if message == "member-output-original")
            );
        } else {
            expected_events.extend([
                vec!["createdAt".into(), "opaque-date".into()].into(),
                vec!["echo".into(), observed_role.clone()].into(),
            ]);
            let role = match mode {
                Mode::Object => shared.clone(),
                Mode::Undefined => FieldValue::Undefined,
                Mode::Null => FieldValue::Null,
                _ => observed_role.clone(),
            };
            let expected = FieldMap::from_iter([
                ("organizationId".into(), 19.into()),
                ("userId".into(), "user-b".into()),
                ("role".into(), role),
                ("createdAt".into(), "opaque-date".into()),
                ("echo".into(), observed_role),
                ("id".into(), "member-b".into()),
            ]);
            let member = required(result?, "Expected ordinary Member point read")?;
            let actual = member.field_values()?;
            let expected = FieldValue::from(expected);
            ordered(&actual.clone().into(), &expected)?;
            assert_eq!(
                serde_json::to_vec(&member)?,
                serde_json::to_vec(&expected.json()?)?
            );
            if matches!(mode, Mode::Object) {
                assert!(
                    actual
                        .get("role")
                        .is_some_and(|value| value.strict_equals(&shared))
                );
            }
        }
    }
    assert_eq!(*trace_lock(&events)?, expected_events, "{entry:?} {mode:?}");
    assert_eq!(storage.snapshot().await?, after, "{entry:?} {mode:?}");
    Ok(())
}

#[tokio::test]
async fn memory_member_point_reads_preserve_live_fields_and_original_errors() -> AuthResult<()> {
    for entry in [Entry::Pair, Entry::NativePair, Entry::Id] {
        for mode in [
            Mode::Live,
            Mode::Object,
            Mode::Undefined,
            Mode::Null,
            Mode::Error,
            Mode::Missing,
        ] {
            let (raw, storage) = memory_fixture();
            check(raw, storage, entry, mode).await?;
        }
    }
    Ok(())
}

#[tokio::test]
async fn sqlite_member_point_reads_preserve_raw_snapshots_and_original_errors() -> AuthResult<()> {
    for entry in [Entry::Pair, Entry::NativePair, Entry::Id] {
        for mode in [
            Mode::Live,
            Mode::Object,
            Mode::Undefined,
            Mode::Null,
            Mode::Error,
            Mode::Missing,
        ] {
            let (raw, storage) = sqlite_fixture().await?;
            check(raw, storage, entry, mode).await?;
        }
    }
    Ok(())
}
