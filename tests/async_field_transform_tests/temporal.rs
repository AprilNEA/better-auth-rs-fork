use super::*;
use better_auth_core::{
    AuthRequest, FieldDate, HttpMethod, Member, Organization, UpdateOrganization,
    hooks::{RequestHookContext, current_request_hook_context, with_request_hook_context_value},
    organization_fields::OrganizationFields,
    store::{StatelessSchema, schema::EntityRole},
};
use better_auth_seaorm::sea_orm::{ConnectionTrait, DatabaseConnection, DbBackend, Statement};
use std::{collections::BTreeMap, time::Duration};

#[derive(Clone, Copy, PartialEq, Eq)]
enum Case {
    User,
    Organization,
}

enum Storage {
    Memory(Box<EphemeralStore>),
    Sqlite(DatabaseConnection),
}

impl Storage {
    async fn snapshot(&self) -> AuthResult<BTreeMap<String, Vec<FieldMap>>> {
        let mut snapshot = BTreeMap::new();
        for (name, table, role) in [
            ("user", "users", EntityRole::User),
            ("session", "sessions", EntityRole::Session),
            ("account", "accounts", EntityRole::Account),
            ("verification", "verifications", EntityRole::Verification),
            ("organization", "organization", EntityRole::Organization),
            ("member", "member", EntityRole::Member),
            ("invitation", "invitation", EntityRole::Invitation),
            ("team", "team", EntityRole::Team),
            ("teamMember", "team_member", EntityRole::TeamMember),
        ] {
            let mut rows = match self {
                Self::Memory(store) => store.storage_rows(role)?,
                Self::Sqlite(database) => {
                    let columns = database
                        .query_all_raw(Statement::from_string(
                            DbBackend::Sqlite,
                            format!("PRAGMA table_info(\"{table}\")"),
                        ))
                        .await
                        .map_err(|error| AuthError::internal(error.to_string()))?;
                    let columns = columns
                        .iter()
                        .map(|row| row.try_get::<String>("", "name"))
                        .collect::<Result<Vec<_>, _>>()
                        .map_err(|error| AuthError::internal(error.to_string()))?;
                    let columns = columns
                        .iter()
                        .map(|name| format!("'{name}',\"{name}\""))
                        .collect::<Vec<_>>()
                        .join(",");
                    database.query_all_raw(Statement::from_string(DbBackend::Sqlite,
                        format!("SELECT json_object({columns}) AS value FROM \"{table}\" ORDER BY id"),
                    )).await.map_err(|error| AuthError::internal(error.to_string()))?
                        .into_iter().map(|row| {
                            let json = row.try_get::<String>("", "value")
                                .map_err(|error| AuthError::internal(error.to_string()))?;
                            FieldMap::from_json(serde_json::from_str(&json)?)
                        }).collect::<AuthResult<Vec<_>>>()?
                }
            };
            rows.sort_by(|left, right| {
                left.get("id")
                    .and_then(FieldValue::as_str)
                    .cmp(&right.get("id").and_then(FieldValue::as_str))
            });
            let _ = snapshot.insert(name.into(), rows);
        }
        Ok(snapshot)
    }
}

fn date() -> FieldDate {
    FieldDate::from_milliseconds(1_893_456_000_000.0)
}

async fn seed<S: AuthSchema>(store: &dyn AuthStore<S>, case: Case) -> AuthResult<()> {
    for name in ["A", "B"] {
        let _ = store
            .create_user(CreateUser {
                id: Some(name.into()),
                created_at: Some(date()),
                updated_at: Some(date()),
                image: Some(format!("{name}.png")).into(),
                ..CreateUser::new()
                    .with_name(name)
                    .with_email(format!("{name}@temporal.test"))
            })
            .await?;
        if case == Case::Organization {
            let _ = store
                .insert_organization(Organization {
                    field_order: Default::default(),
                    additional_fields: Default::default(),
                    id: name.into(),
                    name: name.into(),
                    slug: name.into(),
                    logo: Some(format!("{name}.png")).into(),
                    metadata: None.into(),
                    created_at: date().into(),
                })
                .await?;
            let _ = store
                .insert_member(Member {
                    field_order: Default::default(),
                    additional_fields: Default::default(),
                    id: name.into(),
                    organization_id: name.into(),
                    user_id: "A".into(),
                    role: format!("{name}-parent").into(),
                    created_at: date().into(),
                })
                .await?;
        }
    }
    Ok(())
}

#[expect(
    clippy::panic_in_result_fn,
    reason = "Assertions verify the retained request context and object identity"
)]
fn check_context(marker: &FieldValue) -> AuthResult<()> {
    let context = current_request_hook_context()
        .ok_or_else(|| AuthError::internal("Projection peer lost its request context"))?;
    assert_eq!(context.path.as_deref(), Some("/projection-lifetime"));
    assert_eq!(context.operation_id.as_deref(), Some("projection-lifetime"));
    assert_eq!(
        context.headers.get("x-contract").map(String::as_str),
        Some("projection-lifetime")
    );
    assert!(context.body.strict_equals(marker));
    Ok(())
}

type Event = (&'static str, &'static str, FieldValue);

struct Callbacks<S: AuthSchema> {
    raw: Arc<dyn AuthStore<S>>,
    case: Case,
    gate: Gate,
    marker: FieldValue,
    events: mpsc::UnboundedSender<Event>,
}

impl<S: AuthSchema> Callbacks<S> {
    fn field(&self, name: &'static str) -> UserFieldConfig {
        let callback = self.gate.callback(name);
        let (raw, case, marker, events) = (
            self.raw.clone(),
            self.case,
            self.marker.clone(),
            self.events.clone(),
        );
        UserFieldConfig {
            transform: Some(FieldTransforms {
                output: Some(UserFieldTransform::new_async(move |value| {
                    let (callback, raw, marker, events) = (
                        callback.clone(),
                        raw.clone(),
                        marker.clone(),
                        events.clone(),
                    );
                    async move {
                        check_context(&marker)?;
                        let result = callback.call(value.clone()).await;
                        check_context(&marker)?;
                        if name == "name" && value == FieldValue::from("B") && result.is_ok() {
                            match case {
                                Case::User => {
                                    let _ = raw
                                        .update_user(
                                            "B",
                                            UpdateUser {
                                                image: Some("after-release".into()).into(),
                                                additional_fields: [(
                                                    "updatedAt".into(),
                                                    date().into(),
                                                )]
                                                .into(),
                                                ..Default::default()
                                            },
                                        )
                                        .await?;
                                }
                                Case::Organization => {
                                    let _ = raw
                                        .update_organization(
                                            "B",
                                            UpdateOrganization {
                                                logo: Some(Some("after-release".into())),
                                                ..Default::default()
                                            },
                                        )
                                        .await?;
                                }
                            }
                            check_context(&marker)?;
                        }
                        events
                            .send((
                                if result.is_ok() {
                                    "resolved"
                                } else {
                                    "rejected"
                                },
                                name,
                                value,
                            ))
                            .map_err(|_| {
                                AuthError::internal("Projection event controller closed")
                            })?;
                        result
                    }
                })),
                ..Default::default()
            }),
            ..Default::default()
        }
    }
}

#[expect(
    clippy::panic_in_result_fn,
    reason = "Assertions verify each controlled field callback"
)]
async fn call(
    receiver: &mut mpsc::UnboundedReceiver<Call>,
    field: &str,
    value: &str,
) -> AuthResult<Call> {
    let call = next(receiver).await?;
    assert_eq!(call.field, field);
    assert_eq!(call.value, FieldValue::from(value));
    Ok(call)
}

#[expect(
    clippy::panic_in_result_fn,
    reason = "Assertions verify callback completion order and errors"
)]
async fn completed(
    receiver: &mut mpsc::UnboundedReceiver<Event>,
    status: &str,
    field: &str,
    value: &str,
) -> AuthResult<()> {
    let event = receiver
        .recv()
        .await
        .ok_or_else(|| AuthError::internal("Missing projection completion"))?;
    assert_eq!(event, (status, field, FieldValue::from(value)));
    Ok(())
}

#[expect(
    clippy::panic_in_result_fn,
    reason = "Assertions verify early error delivery, retained peers, and complete storage"
)]
async fn check<S: AuthSchema>(
    raw: Arc<dyn AuthStore<S>>,
    storage: Storage,
    case: Case,
) -> AuthResult<()> {
    seed(raw.as_ref(), case).await?;
    let before = storage.snapshot().await?;
    let marker: FieldValue =
        FieldMap::from_iter([("identity".into(), "retained-body".into())]).into();
    let gate = Gate::default();
    let mut calls = gate.arm()?;
    let (events, mut completions) = mpsc::unbounded_channel();
    let callbacks = Callbacks {
        raw: raw.clone(),
        case,
        gate: gate.clone(),
        marker: marker.clone(),
        events,
    };
    let mut config = AuthConfig::default();
    if case == Case::User {
        let _ = config
            .user
            .fields_mut()
            .insert("name".into(), callbacks.field("name"));
        let _ = config
            .user
            .fields_mut()
            .insert("image".into(), callbacks.field("image"));
    }
    let reader = raw.with_runtime(config.into(), Vec::new(), Default::default())?;
    if case == Case::Organization {
        let mut fields = OrganizationFields::default();
        let _ = fields
            .member
            .fields_mut()
            .insert("role".into(), callbacks.field("parent"));
        let _ = fields
            .organization
            .fields_mut()
            .insert("name".into(), callbacks.field("name"));
        let _ = fields
            .organization
            .fields_mut()
            .insert("logo".into(), callbacks.field("image"));
        reader.configure_organization_fields(fields)?;
    }
    let mut context = RequestHookContext::from_request(&AuthRequest::new(
        HttpMethod::Get,
        "/projection-lifetime",
    ))?;
    context.operation_id = Some("projection-lifetime".into());
    let _ = context
        .headers
        .insert("x-contract".into(), "projection-lifetime".into());
    context.body = marker;
    let pending = tokio::spawn(with_request_hook_context_value(context, async move {
        match case {
            Case::User => reader
                .list_users(ListUsersParams {
                    sort_by: Some("email".into()),
                    sort_direction: Some("asc".into()),
                    ..Default::default()
                })
                .await
                .map(|_| ()),
            Case::Organization => reader.list_user_organizations("A").await.map(|_| ()),
        }
    }));

    let first = next(&mut calls).await?;
    let second = next(&mut calls).await?;
    let (a, b) =
        if first.value == FieldValue::from(if case == Case::User { "A" } else { "A-parent" }) {
            (first, second)
        } else {
            (second, first)
        };
    let (a, peer) = if case == Case::Organization {
        assert_eq!((a.field, b.field), ("parent", "parent"));
        assert_eq!(a.value, FieldValue::from("A-parent"));
        assert_eq!(b.value, FieldValue::from("B-parent"));
        answer(a, Ok(Some(json!("A-parent"))))?;
        completed(&mut completions, "resolved", "parent", "A-parent").await?;
        (call(&mut calls, "name", "A").await?, b)
    } else {
        assert_eq!((a.field, b.field), ("name", "name"));
        assert_eq!(a.value, FieldValue::from("A"));
        assert_eq!(b.value, FieldValue::from("B"));
        (a, b)
    };
    let original = String::from("original-projection-error");
    let original_pointer = original.as_ptr() as usize;
    answer(a, Err(AuthError::Config(original)))?;
    let outcome = tokio::time::timeout(Duration::from_secs(5), pending)
        .await
        .map_err(|_| {
            AuthError::internal("The original error must return while the peer gate remains closed")
        })?
        .map_err(|error| AuthError::internal(error.to_string()))?;
    let error = match outcome {
        Err(AuthError::Config(error)) => error,
        other => {
            return Err(AuthError::internal(format!(
                "Expected the original Config error, got {other:?}"
            )));
        }
    };
    assert_eq!(error, "original-projection-error");
    assert_eq!(error.as_ptr() as usize, original_pointer);
    assert!(
        !peer.reply.is_closed(),
        "The returned error must retain the blocked peer"
    );
    assert!(current_request_hook_context().is_none());
    completed(&mut completions, "rejected", "name", "A").await?;
    assert_eq!(storage.snapshot().await?, before);

    let peer = if case == Case::Organization {
        answer(peer, Ok(Some(json!("B-parent"))))?;
        completed(&mut completions, "resolved", "parent", "B-parent").await?;
        call(&mut calls, "name", "B").await?
    } else {
        peer
    };
    let write_started = chrono::Utc::now().timestamp_millis();
    answer(peer, Ok(Some(json!("B-visible"))))?;
    completed(&mut completions, "resolved", "name", "B").await?;
    let write_finished = chrono::Utc::now().timestamp_millis();
    let source = if matches!(storage, Storage::Memory(_)) {
        "after-release"
    } else {
        "B.png"
    };
    let image = call(&mut calls, "image", source).await?;
    if case == Case::Organization {
        answer(image, Err(AuthError::Config("late-peer-error".into())))?;
        completed(&mut completions, "rejected", "image", source).await?;
    } else {
        answer(image, Ok(Some(json!("B-image-visible"))))?;
        completed(&mut completions, "resolved", "image", source).await?;
    }
    assert_eq!(error.as_ptr() as usize, original_pointer);
    assert!(current_request_hook_context().is_none());
    assert!(matches!(
        calls.try_recv(),
        Err(mpsc::error::TryRecvError::Empty)
    ));
    assert!(matches!(
        completions.try_recv(),
        Err(mpsc::error::TryRecvError::Empty)
    ));
    let actual = storage.snapshot().await?;
    let mut expected = before;
    let model = if case == Case::User {
        "user"
    } else {
        "organization"
    };
    let row = expected
        .get_mut(model)
        .and_then(|rows| {
            rows.iter_mut()
                .find(|row| row.get("id") == Some(&FieldValue::from("B")))
        })
        .ok_or_else(|| AuthError::internal("Missing expected peer storage"))?;
    let _ = row.insert(
        if case == Case::User { "image" } else { "logo" }.into(),
        "after-release".into(),
    );
    if let (Case::Organization, Storage::Sqlite(database)) = (case, &storage) {
        let stored = database
            .query_one_raw(Statement::from_string(
                DbBackend::Sqlite,
                "SELECT updated_at FROM organization WHERE id = 'B'",
            ))
            .await
            .map_err(|error| AuthError::internal(error.to_string()))?
            .ok_or_else(|| AuthError::internal("Expected private Organization timestamp"))?;
        let timestamp = stored
            .try_get::<chrono::DateTime<chrono::Utc>>("", "updated_at")
            .map_err(|error| AuthError::internal(error.to_string()))?;
        assert!((write_started..=write_finished).contains(&timestamp.timestamp_millis()));
        let observed = actual
            .get("organization")
            .and_then(|rows| {
                rows.iter()
                    .find(|row| row.get("id").and_then(FieldValue::as_str) == Some("B"))
            })
            .and_then(|row| row.get("updated_at"))
            .ok_or_else(|| AuthError::internal("Expected stored private Organization timestamp"))?;
        let _ = row.insert("updated_at".into(), observed.clone());
    }
    assert_eq!(actual, expected);
    gate.disarm()?;
    Ok(())
}

async fn memory(case: Case) -> AuthResult<()> {
    let raw = EphemeralStore::default();
    let store: Arc<dyn AuthStore<StatelessSchema>> = Arc::new(raw.clone());
    tokio::time::timeout(
        Duration::from_secs(10),
        check(store, Storage::Memory(Box::new(raw)), case),
    )
    .await
    .map_err(|_| {
        AuthError::internal(
            "Temporal projection contract must finish without opening a blocked gate early",
        )
    })?
}

async fn sql(case: Case) -> AuthResult<()> {
    let database = Database::connect("sqlite::memory:")
        .await
        .map_err(|error| AuthError::internal(error.to_string()))?;
    migrator::run_migrations(&database)
        .await
        .map_err(|error| AuthError::internal(error.to_string()))?;
    let store: Arc<dyn AuthStore<BundledSchema>> =
        Arc::new(SeaOrmStore::new(AuthConfig::default(), database.clone()));
    tokio::time::timeout(
        Duration::from_secs(10),
        check(store, Storage::Sqlite(database), case),
    )
    .await
    .map_err(|_| {
        AuthError::internal(
            "Temporal projection contract must finish without opening a blocked gate early",
        )
    })?
}

#[tokio::test]
async fn memory_user_error_returns_before_live_peer_continues() -> AuthResult<()> {
    memory(Case::User).await
}

#[tokio::test]
async fn sqlite_user_error_returns_before_snapshot_peer_continues() -> AuthResult<()> {
    sql(Case::User).await
}

#[tokio::test]
async fn memory_continuation_error_retains_live_peer_and_late_error() -> AuthResult<()> {
    memory(Case::Organization).await
}

#[tokio::test]
async fn sqlite_continuation_error_retains_snapshot_peer_and_late_error() -> AuthResult<()> {
    sql(Case::Organization).await
}
