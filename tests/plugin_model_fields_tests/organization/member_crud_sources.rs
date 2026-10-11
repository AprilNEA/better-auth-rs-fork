use super::member_contract_support::*;
use super::*;
use better_auth_core::id::{IdGeneration, IdGenerator};
use better_auth_core::store::ListOrganizationMembersParams;
use better_auth_core::{AuthRecordFields, CreateMember, Member, SchemaValue};
use std::sync::atomic::{AtomicUsize, Ordering};
use tokio::sync::Notify;

#[path = "organization_model_crud_sources.rs"]
mod models;

type Events = Arc<Mutex<Vec<FieldValue>>>;
type Snapshot = std::collections::BTreeMap<String, Vec<FieldMap>>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Write {
    Insert,
    Create,
    Update,
}

impl Write {
    fn id(self) -> &'static str {
        match self {
            Self::Insert => "insert-member",
            Self::Create => "created-member",
            Self::Update => "member-b",
        }
    }

    fn source(self) -> &'static str {
        match self {
            Self::Insert => "insert-source",
            Self::Create => "create-source",
            Self::Update => "update-source",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Mode {
    Success,
    InputError,
    OutputError,
    Live,
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

fn event(events: &Events, field: &str, phase: &str, value: FieldValue) -> AuthResult<()> {
    trace_lock(events)?.push(vec![field.into(), phase.into(), value].into());
    Ok(())
}

fn physical(storage: &Storage, id: &str, user: &str, role: &str, created: FieldValue) -> FieldMap {
    FieldMap::from_iter([
        ("id".into(), id.into()),
        (
            if storage.memory() {
                "organizationId"
            } else {
                "organization_id"
            }
            .into(),
            "organization".into(),
        ),
        (
            if storage.memory() {
                "userId"
            } else {
                "user_id"
            }
            .into(),
            user.into(),
        ),
        ("role".into(), role.into()),
        (
            if storage.memory() {
                "createdAt"
            } else {
                "created_at"
            }
            .into(),
            created,
        ),
    ])
}

fn stored_date(storage: &Storage) -> FieldValue {
    if storage.memory() {
        date().into()
    } else {
        "2030-01-01T00:00:00.000Z".into()
    }
}

fn visible(id: &str, user: &str, role: &str, created: FieldValue) -> FieldValue {
    FieldMap::from_iter([
        ("organizationId".into(), "organization".into()),
        ("userId".into(), user.into()),
        ("role".into(), role.into()),
        ("createdAt".into(), created),
        ("id".into(), id.into()),
    ])
    .into()
}

fn replace(snapshot: &mut Snapshot, row: FieldMap) -> AuthResult<()> {
    let rows = snapshot
        .get_mut("member")
        .ok_or_else(|| AuthError::internal("Expected Member table"))?;
    rows.retain(|existing| existing.get("id") != row.get("id"));
    rows.push(row);
    rows.sort_by(|left, right| {
        left.get("id")
            .and_then(FieldValue::as_str)
            .cmp(&right.get("id").and_then(FieldValue::as_str))
    });
    Ok(())
}

#[expect(
    clippy::panic_in_result_fn,
    reason = "Contract assertions report mismatches while setup and callback errors propagate"
)]
fn check_member(actual: &Member, expected: &FieldValue) -> AuthResult<()> {
    ordered(&actual.field_values()?.into(), expected)?;
    assert_eq!(
        serde_json::to_vec(actual)?,
        serde_json::to_vec(&expected.json()?)?
    );
    Ok(())
}

async fn write<S: AuthSchema>(store: &dyn AuthStore<S>, operation: Write) -> AuthResult<Member> {
    match operation {
        Write::Insert => {
            let mut row = member(operation.id(), "user-b", "requested");
            row.created_at = SchemaValue::from_field(operation.source().into());
            store.insert_member(row).await
        }
        Write::Create => {
            store
                .create_member(CreateMember::new("organization", "user-b", "requested"))
                .await
        }
        Write::Update => {
            store
                .update_member_role_value(&operation.id().into(), "requested")
                .await
        }
    }
}

async fn check_write<S: AuthSchema>(
    raw: Arc<dyn AuthStore<S>>,
    storage: Storage,
    operation: Write,
    mode: Mode,
) -> AuthResult<()> {
    let _ = seed(raw.clone(), operation == Write::Update, "user-a").await?;
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
    let before = storage.snapshot().await?;
    let events = Events::default();
    let shared: FieldValue =
        FieldMap::from_iter([("native".into(), operation.source().into())]).into();
    let policies = declaration([
        (
            "organizationId",
            UserFieldConfig {
                transform: (mode == Mode::Live).then(|| FieldTransforms {
                    output: Some(UserFieldTransform::new_async({
                        let events = events.clone();
                        let writer = writer.store().clone();
                        move |value| {
                            let events = events.clone();
                            let writer = writer.clone();
                            async move {
                                event(&events, "organizationId", "output", value.clone())?;
                                let _ =
                                    writer.update_member_role(operation.id(), "changed").await?;
                                Ok(value)
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
                    input: Some(UserFieldTransform::new({
                        let events = events.clone();
                        move |value| {
                            event(&events, "role", "input", value.clone())?;
                            Ok(value)
                        }
                    })),
                    output: Some(UserFieldTransform::new({
                        let events = events.clone();
                        move |value| {
                            event(&events, "role", "output", value.clone())?;
                            Ok(value)
                        }
                    })),
                }),
                ..Default::default()
            },
        ),
        (
            "createdAt",
            UserFieldConfig {
                on_update: Some(Arc::new({
                    let events = events.clone();
                    move || {
                        event(&events, "createdAt", "onUpdate", FieldValue::Undefined)?;
                        Ok("update-source".into())
                    }
                })),
                transform: Some(FieldTransforms {
                    input: Some(UserFieldTransform::new({
                        let events = events.clone();
                        move |value| {
                            let input = if operation == Write::Create {
                                assert!(
                                    value.as_date().is_some(),
                                    "Member creation supplies a native Date"
                                );
                                "native-date".into()
                            } else {
                                value.clone()
                            };
                            event(&events, "createdAt", "input", input)?;
                            if mode == Mode::InputError {
                                return Err(AuthError::Forbidden("member-input-original".into()));
                            }
                            let source = if operation == Write::Create {
                                operation.source()
                            } else {
                                required(value.as_str(), "Expected declared string timestamp")?
                            };
                            Ok(format!("stored:{source}").into())
                        }
                    })),
                    output: Some(UserFieldTransform::new({
                        let events = events.clone();
                        let shared = shared.clone();
                        move |value| {
                            event(&events, "createdAt", "output", value)?;
                            if mode == Mode::OutputError {
                                return Err(AuthError::Forbidden("member-output-original".into()));
                            }
                            Ok(shared.clone())
                        }
                    })),
                }),
                ..Default::default()
            },
        ),
    ]);
    let mut settings = config();
    settings.advanced.database.generate_id = Some(IdGeneration::Custom(IdGenerator::new(|_| {
        Ok(Some("created-member".into()))
    })));
    let auth = BetterAuth::new(settings)
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
        .plugin(Fields(vec![(EntityRole::Member, policies)]))
        .build()
        .await?;
    let result = write(auth.store().as_ref(), operation).await;
    let mut expected_events: Vec<FieldValue> =
        vec![vec!["role".into(), "input".into(), "requested".into()].into()];
    if operation == Write::Update {
        expected_events
            .push(vec!["createdAt".into(), "onUpdate".into(), FieldValue::Undefined].into());
    }
    expected_events.push(
        vec![
            "createdAt".into(),
            "input".into(),
            if operation == Write::Create {
                "native-date"
            } else {
                operation.source()
            }
            .into(),
        ]
        .into(),
    );
    let mut after = before;
    if mode == Mode::InputError {
        assert!(
            matches!(result, Err(AuthError::Forbidden(message)) if message == "member-input-original")
        );
    } else {
        let role = if mode == Mode::Live && storage.memory() {
            "changed"
        } else {
            "requested"
        };
        if mode == Mode::Live {
            expected_events.push(
                vec![
                    "organizationId".into(),
                    "output".into(),
                    "organization".into(),
                ]
                .into(),
            );
        }
        expected_events.extend([
            vec!["role".into(), "output".into(), role.into()].into(),
            vec![
                "createdAt".into(),
                "output".into(),
                format!("stored:{}", operation.source()).into(),
            ]
            .into(),
        ]);
        replace(
            &mut after,
            physical(
                &storage,
                operation.id(),
                "user-b",
                if mode == Mode::Live {
                    "changed"
                } else {
                    "requested"
                },
                format!("stored:{}", operation.source()).into(),
            ),
        )?;
        if mode == Mode::OutputError {
            assert!(
                matches!(result, Err(AuthError::Forbidden(message)) if message == "member-output-original")
            );
        } else {
            let actual = result?;
            check_member(
                &actual,
                &visible(operation.id(), "user-b", role, shared.clone()),
            )?;
            assert!(actual.created_at.field_value().strict_equals(&shared));
        }
    }
    ordered(
        &trace_lock(&events)?.clone().into(),
        &expected_events.into(),
    )?;
    assert_eq!(storage.snapshot().await?, after, "{operation:?} {mode:?}");
    Ok(())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum List {
    Ordinary,
    Native,
    Query,
}

async fn check_list<S: AuthSchema>(
    raw: Arc<dyn AuthStore<S>>,
    storage: Storage,
    entry: List,
) -> AuthResult<()> {
    let _ = seed(raw.clone(), false, "user-a").await?;
    raw.delete_member("owner-member").await?;
    for (id, role) in [("member-a", "10"), ("member-b", "20")] {
        let _ = raw.insert_member(member(id, "user-b", role)).await?;
    }
    if entry == List::Query {
        for (id, role) in [("member-skip", "00"), ("member-tail", "30")] {
            let _ = raw.insert_member(member(id, "user-b", role)).await?;
        }
    }
    let before = storage.snapshot().await?;
    let events = Events::default();
    let release = Arc::new(Notify::new());
    let calls = Arc::new(AtomicUsize::new(0));
    let policies = declaration([
        (
            "organizationId",
            UserFieldConfig {
                transform: Some(FieldTransforms {
                    output: Some(UserFieldTransform::new_async({
                        let raw = raw.clone();
                        let events = events.clone();
                        let release = release.clone();
                        let calls = calls.clone();
                        move |value| {
                            let raw = raw.clone();
                            let events = events.clone();
                            let release = release.clone();
                            let first = calls.fetch_add(1, Ordering::SeqCst) == 0;
                            async move {
                                event(&events, "organizationId", "output", value.clone())?;
                                if first {
                                    release.notified().await;
                                    let _ = raw.update_member_role("member-a", "90").await?;
                                    raw.delete_member("member-a").await?;
                                    let _ = raw
                                        .insert_member(member("member-a", "user-a", "replacement"))
                                        .await?;
                                    let _ = raw.update_member_role("member-b", "after-b").await?;
                                    let _ = raw
                                        .insert_member(member("member-new", "user-b", "00-new"))
                                        .await?;
                                }
                                Ok(value)
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
                        move |value| {
                            event(&events, "role", "output", value.clone())?;
                            Ok(value)
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
                field_type: UserFieldType::Date,
                transform: Some(FieldTransforms {
                    output: Some(UserFieldTransform::new({
                        let events = events.clone();
                        move |value| {
                            event(&events, "createdAt", "output", value.clone())?;
                            release.notify_one();
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
        .plugin(Fields(vec![(EntityRole::Member, policies)]))
        .build()
        .await?;
    let rows = tokio::time::timeout(std::time::Duration::from_secs(5), async {
        Ok::<_, AuthError>(match entry {
            List::Ordinary => {
                auth.store()
                    .list_organization_members("organization")
                    .await?
            }
            List::Native => {
                auth.store()
                    .list_organization_members_value(&"organization".into())
                    .await?
            }
            List::Query => {
                let (rows, total) = auth
                    .store()
                    .query_organization_members(&ListOrganizationMembersParams {
                        organization_id: "organization".into(),
                        limit: Some(2.0),
                        offset: Some(1.0),
                        sort_by: Some("role".into()),
                        sort_direction: Some("asc".into()),
                        ..Default::default()
                    })
                    .await?;
                assert_eq!(total, 4);
                rows
            }
        })
    })
    .await
    .map_err(|_| AuthError::internal(format!("Member {entry:?} output callbacks stalled")))??;
    let first_role = if storage.memory() { "90" } else { "10" };
    assert_eq!(rows.len(), 2);
    for (row, expected) in rows.iter().zip([
        visible("member-a", "user-b", first_role, date().into()),
        visible("member-b", "user-b", "20", date().into()),
    ]) {
        check_member(row, &expected)?;
    }
    let expected_events: Vec<FieldValue> = [
        vec![
            "organizationId".into(),
            "output".into(),
            "organization".into(),
        ],
        vec![
            "organizationId".into(),
            "output".into(),
            "organization".into(),
        ],
        vec!["role".into(), "output".into(), "20".into()],
        vec!["createdAt".into(), "output".into(), stored_date(&storage)],
        vec!["role".into(), "output".into(), first_role.into()],
        vec!["createdAt".into(), "output".into(), stored_date(&storage)],
    ]
    .into_iter()
    .map(FieldValue::from)
    .collect();
    ordered(
        &trace_lock(&events)?.clone().into(),
        &expected_events.into(),
    )?;
    let mut after = before;
    for (id, user, role) in [
        ("member-a", "user-a", "replacement"),
        ("member-b", "user-b", "after-b"),
        ("member-new", "user-b", "00-new"),
    ] {
        replace(
            &mut after,
            physical(&storage, id, user, role, stored_date(&storage)),
        )?;
    }
    assert_eq!(storage.snapshot().await?, after, "{entry:?}");
    Ok(())
}

async fn duplicate_memory(mode: Mode) -> AuthResult<()> {
    let (raw, storage) = memory_fixture();
    let _ = seed(raw.clone(), false, "user-a").await?;
    for (user, role) in [("user-a", "first"), ("user-b", "second")] {
        let _ = raw.insert_member(member("duplicate", user, role)).await?;
    }
    let mut after = storage.snapshot().await?;
    let events = Events::default();
    let auth = BetterAuth::new(config())
        .store_arc(raw)
        .plugin(OrganizationPlugin::with_config(
            OrganizationConfig::default(),
        ))
        .plugin(Fields(vec![(
            EntityRole::Member,
            declaration([(
                "role",
                UserFieldConfig {
                    transform: Some(FieldTransforms {
                        input: Some(UserFieldTransform::new({
                            let events = events.clone();
                            move |value| {
                                event(&events, "role", "input", value.clone())?;
                                if mode == Mode::InputError {
                                    return Err(AuthError::Forbidden(
                                        "duplicate-input-original".into(),
                                    ));
                                }
                                Ok(value)
                            }
                        })),
                        output: Some(UserFieldTransform::new({
                            let events = events.clone();
                            move |value| {
                                event(&events, "role", "output", value.clone())?;
                                if mode == Mode::OutputError {
                                    return Err(AuthError::Forbidden(
                                        "duplicate-output-original".into(),
                                    ));
                                }
                                Ok(value)
                            }
                        })),
                    }),
                    ..Default::default()
                },
            )]),
        )]))
        .build()
        .await?;
    let result = auth
        .store()
        .update_member_role("duplicate", "updated")
        .await;
    let mut expected_events: Vec<FieldValue> =
        vec![vec!["role".into(), "input".into(), "updated".into()].into()];
    if mode == Mode::InputError {
        assert!(
            matches!(result, Err(AuthError::Forbidden(message)) if message == "duplicate-input-original")
        );
    } else {
        expected_events.push(vec!["role".into(), "output".into(), "updated".into()].into());
        for row in after
            .get_mut("member")
            .ok_or_else(|| AuthError::internal("Expected Member table"))?
        {
            if row.get("id").and_then(FieldValue::as_str) == Some("duplicate") {
                let _ = row.insert("role".into(), "updated".into());
            }
        }
        if mode == Mode::OutputError {
            assert!(
                matches!(result, Err(AuthError::Forbidden(message)) if message == "duplicate-output-original")
            );
        } else {
            check_member(
                &result?,
                &visible("duplicate", "user-a", "updated", date().into()),
            )?;
        }
    }
    ordered(
        &trace_lock(&events)?.clone().into(),
        &expected_events.into(),
    )?;
    assert_eq!(storage.snapshot().await?, after);
    Ok(())
}

#[tokio::test]
async fn memory_member_crud_preserves_live_records_and_write_failures() -> AuthResult<()> {
    for operation in [Write::Insert, Write::Create, Write::Update] {
        for mode in [
            Mode::Success,
            Mode::InputError,
            Mode::OutputError,
            Mode::Live,
        ] {
            let (raw, storage) = memory_fixture();
            check_write(raw, storage, operation, mode).await?;
        }
    }
    for entry in [List::Ordinary, List::Native, List::Query] {
        let (raw, storage) = memory_fixture();
        check_list(raw, storage, entry).await?;
    }
    for mode in [Mode::Success, Mode::InputError, Mode::OutputError] {
        duplicate_memory(mode).await?;
    }
    Ok(())
}

#[tokio::test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "Contract assertions report mismatches while setup and callback errors propagate"
)]
async fn sqlite_member_crud_preserves_raw_snapshots_and_write_failures() -> AuthResult<()> {
    for operation in [Write::Insert, Write::Create, Write::Update] {
        for mode in [
            Mode::Success,
            Mode::InputError,
            Mode::OutputError,
            Mode::Live,
        ] {
            let (raw, storage) = sqlite_fixture().await?;
            check_write(raw, storage, operation, mode).await?;
        }
    }
    for entry in [List::Ordinary, List::Native, List::Query] {
        let (raw, storage) = sqlite_fixture().await?;
        check_list(raw, storage, entry).await?;
    }
    let (raw, storage) = sqlite_fixture().await?;
    let _ = seed(raw.clone(), false, "user-a").await?;
    let _ = raw
        .insert_member(member("duplicate", "user-a", "first"))
        .await?;
    let before = storage.snapshot().await?;
    let error = raw
        .insert_member(member("duplicate", "user-b", "second"))
        .await
        .err()
        .ok_or_else(|| AuthError::internal("Expected SQLite duplicate ID failure"))?;
    assert!(matches!(error, AuthError::Database(_)));
    assert!(
        error
            .to_string()
            .contains("UNIQUE constraint failed: member.id"),
        "{error:?}"
    );
    assert_eq!(storage.snapshot().await?, before);
    Ok(())
}
