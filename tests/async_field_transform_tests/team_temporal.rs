use super::*;
use super::{adapter_storage_snapshot::Storage, field_projection_gate::Call as ProjectionCall};
use better_auth_core::{
    AuthInitContext, AuthRequest, CreateTeam, FieldDate, HttpMethod, Organization, UpdateTeam,
    hooks::{RequestHookContext, current_request_hook_context, with_request_hook_context_value},
    organization_fields::OrganizationFields,
    store::{StatelessSchema, schema::EntityRole},
    user_fields::UserFieldReference,
};
use std::time::Duration;

const TABLES: &[(&str, &str, EntityRole)] = &[
    ("user", "users", EntityRole::User),
    ("session", "sessions", EntityRole::Session),
    ("account", "accounts", EntityRole::Account),
    ("verification", "verifications", EntityRole::Verification),
    ("organization", "organization", EntityRole::Organization),
    ("member", "member", EntityRole::Member),
    ("invitation", "invitation", EntityRole::Invitation),
    ("team", "team", EntityRole::Team),
    ("teamMember", "team_member", EntityRole::TeamMember),
];

fn date() -> FieldDate {
    FieldDate::from_milliseconds(1_893_456_000_000.0)
}

async fn seed<S: AuthSchema>(store: &dyn AuthStore<S>) -> AuthResult<()> {
    let _ = store
        .create_user(CreateUser {
            id: Some("user".into()),
            created_at: Some(date()),
            updated_at: Some(date()),
            ..CreateUser::new()
                .with_name("User")
                .with_email("user@team-temporal.test")
        })
        .await?;
    let _ = store
        .insert_organization(Organization {
            field_order: Default::default(),
            additional_fields: Default::default(),
            id: "organization".into(),
            name: "Organization".into(),
            slug: "organization".into(),
            logo: None.into(),
            metadata: None.into(),
            created_at: date().into(),
        })
        .await?;
    for name in ["A", "B"] {
        let _ = store
            .create_team(CreateTeam {
                id: Some(name.into()),
                name: name.into(),
                organization_id: "organization".into(),
                created_at: Some(date()),
                updated_at: Some(date()),
                ..Default::default()
            })
            .await?;
        let _ = store
            .add_team_member(&name.into(), "user", None)
            .await?
            .ok_or_else(|| AuthError::internal("Expected TeamMember seed"))?;
        let _ = store
            .update_team(
                name,
                UpdateTeam {
                    updated_at: Some(Some(date())),
                    ..Default::default()
                },
            )
            .await?;
    }
    Ok(())
}

#[expect(
    clippy::panic_in_result_fn,
    reason = "The retained callback must preserve request context and native body identity"
)]
fn check_context(marker: &FieldValue) -> AuthResult<()> {
    let context = current_request_hook_context()
        .ok_or_else(|| AuthError::internal("Team projection peer lost its request context"))?;
    assert_eq!(context.path.as_deref(), Some("/team-projection-lifetime"));
    assert_eq!(
        context.operation_id.as_deref(),
        Some("team-projection-lifetime")
    );
    assert_eq!(
        context.headers.get("x-contract").map(String::as_str),
        Some("team-projection-lifetime")
    );
    assert_eq!(context.request.path(), "/team-projection-lifetime");
    assert_eq!(
        context
            .request
            .headers
            .get("x-contract")
            .map(String::as_str),
        Some("team-projection-lifetime")
    );
    assert!(context.body.strict_equals(marker));
    Ok(())
}

type Completion = (bool, &'static str, FieldValue);

struct Callbacks<S: AuthSchema> {
    raw: Arc<dyn AuthStore<S>>,
    marker: FieldValue,
    calls: mpsc::UnboundedSender<ProjectionCall>,
    completions: mpsc::UnboundedSender<Completion>,
}

impl<S: AuthSchema> Callbacks<S> {
    fn field(&self, name: &'static str) -> UserFieldConfig {
        let callback = field_projection_gate::callback(&self.calls, name, std::convert::identity);
        let (raw, marker, completions) = (
            self.raw.clone(),
            self.marker.clone(),
            self.completions.clone(),
        );
        UserFieldConfig {
            transform: Some(FieldTransforms {
                output: Some(UserFieldTransform::new_async(move |value| {
                    let (callback, raw, marker, completions) = (
                        callback.clone(),
                        raw.clone(),
                        marker.clone(),
                        completions.clone(),
                    );
                    async move {
                        check_context(&marker)?;
                        let result = callback.call(value.clone()).await;
                        check_context(&marker)?;
                        if name == "name" && value == FieldValue::from("B") && result.is_ok() {
                            let _ = raw
                                .update_team(
                                    "B",
                                    UpdateTeam {
                                        additional_fields: [("memberCount".into(), 7.0.into())]
                                            .into(),
                                        updated_at: Some(Some(date())),
                                        ..Default::default()
                                    },
                                )
                                .await?;
                            check_context(&marker)?;
                        }
                        completions
                            .send((result.is_ok(), name, value))
                            .map_err(|_| {
                                AuthError::internal("Team completion controller closed")
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

async fn next_call(
    receiver: &mut mpsc::UnboundedReceiver<ProjectionCall>,
) -> AuthResult<ProjectionCall> {
    receiver
        .recv()
        .await
        .ok_or_else(|| AuthError::internal("Missing Team projection callback"))
}

fn answer(call: ProjectionCall, result: AuthResult<FieldValue>) -> AuthResult<()> {
    call.reply
        .send(result)
        .map_err(|_| AuthError::internal("Team projection callback was cancelled"))
}

async fn completed(
    receiver: &mut mpsc::UnboundedReceiver<Completion>,
    success: bool,
    name: &'static str,
    value: FieldValue,
) -> AuthResult<()> {
    let event = receiver
        .recv()
        .await
        .ok_or_else(|| AuthError::internal("Missing Team projection completion"))?;
    assert_eq!(event, (success, name, value));
    Ok(())
}

async fn check<S: AuthSchema>(
    raw: Arc<dyn AuthStore<S>>,
    storage: Storage,
    joins: bool,
) -> AuthResult<()> {
    seed(raw.as_ref()).await?;
    let before = storage.snapshot(TABLES).await?;
    let marker: FieldValue =
        FieldMap::from_iter([("identity".into(), "retained-team-body".into())]).into();
    let (calls, mut receiver) = mpsc::unbounded_channel();
    let (completions, mut finished) = mpsc::unbounded_channel();
    let callbacks = Callbacks {
        raw: raw.clone(),
        marker: marker.clone(),
        calls,
        completions,
    };
    let mut config = AuthConfig::default();
    config.advanced.database.joins = Some(joins);
    let mut membership = UserConfig::default();
    let mut fields = OrganizationFields::default();
    for (name, model) in [("teamId", "team"), ("userId", "user")] {
        let mut field = callbacks.field(name);
        field.references = Some(UserFieldReference {
            model: model.into(),
            field: "id".into(),
            ..Default::default()
        });
        let _ = membership.fields_mut().insert(name.into(), field);
    }
    let _ = fields
        .team
        .fields_mut()
        .insert("name".into(), callbacks.field("name"));
    let mut count = callbacks.field("memberCount");
    count.field_type = better_auth_core::user_fields::UserFieldType::Number;
    let _ = fields.team.fields_mut().insert("memberCount".into(), count);
    let config = Arc::new(config);
    let initial = raw.with_runtime(config.clone(), Vec::new(), Default::default())?;
    let mut init = AuthInitContext::new(config.clone(), initial);
    init.register_organization_schema(&fields, true, false);
    init.register_model_fields(EntityRole::TeamMember, membership)?;
    let reader = raw.with_runtime(config, Vec::new(), init.into_parts().plugin_fields)?;
    let mut request = AuthRequest::new(HttpMethod::Get, "/team-projection-lifetime");
    let _ = request
        .headers
        .insert("x-contract".into(), "team-projection-lifetime".into());
    let mut context = RequestHookContext::from_request(&request)?;
    context.operation_id = Some("team-projection-lifetime".into());
    context.body = marker;
    let pending = tokio::spawn(with_request_hook_context_value(context, async move {
        reader.list_user_teams("user").await
    }));
    let first = next_call(&mut receiver).await?;
    let second = next_call(&mut receiver).await?;
    let (a, peer) = if first.value == FieldValue::from("A") {
        (first, second)
    } else {
        (second, first)
    };
    assert_eq!((a.name, peer.name), ("teamId", "teamId"));
    assert_eq!(a.value, FieldValue::from("A"));
    assert_eq!(peer.value, FieldValue::from("B"));
    let original = String::from("original-team-parent-error");
    let original_pointer = original.as_ptr() as usize;
    answer(a, Err(AuthError::Config(original)))?;
    let outcome = tokio::time::timeout(Duration::from_secs(5), pending)
        .await
        .map_err(|_| {
            AuthError::internal("Team parent error must return while peer gate remains closed")
        })?
        .map_err(|error| AuthError::internal(error.to_string()))?;
    let error = match outcome {
        Err(AuthError::Config(error)) => error,
        other => {
            return Err(AuthError::internal(format!(
                "Expected original Team parent error, got {other:?}"
            )));
        }
    };
    assert_eq!(error, "original-team-parent-error");
    assert_eq!(error.as_ptr() as usize, original_pointer);
    assert!(
        !peer.reply.is_closed(),
        "The returned parent error must retain its blocked peer"
    );
    assert!(current_request_hook_context().is_none());
    completed(&mut finished, false, "teamId", "A".into()).await?;
    assert_eq!(storage.snapshot(TABLES).await?, before);
    answer(peer, Ok("B".into()))?;
    completed(&mut finished, true, "teamId", "B".into()).await?;
    let user = next_call(&mut receiver).await?;
    assert_eq!(
        (user.name, &user.value),
        ("userId", &FieldValue::from("user"))
    );
    answer(user, Ok("user".into()))?;
    completed(&mut finished, true, "userId", "user".into()).await?;
    let name = next_call(&mut receiver).await?;
    assert_eq!((name.name, &name.value), ("name", &FieldValue::from("B")));
    answer(name, Ok("B-visible".into()))?;
    completed(&mut finished, true, "name", "B".into()).await?;
    let expected_count = if matches!(storage, Storage::Memory(_)) {
        7.0
    } else {
        1.0
    };
    let count = next_call(&mut receiver).await?;
    assert_eq!(
        (count.name, &count.value),
        ("memberCount", &FieldValue::from(expected_count))
    );
    answer(count, Err(AuthError::Config("late-team-peer-error".into())))?;
    completed(&mut finished, false, "memberCount", expected_count.into()).await?;
    assert_eq!(error.as_ptr() as usize, original_pointer);
    assert!(current_request_hook_context().is_none());
    assert!(matches!(
        receiver.try_recv(),
        Err(mpsc::error::TryRecvError::Empty)
    ));
    assert!(matches!(
        finished.try_recv(),
        Err(mpsc::error::TryRecvError::Empty)
    ));
    let mut expected = before;
    let row = expected
        .get_mut("team")
        .and_then(|rows| {
            rows.iter_mut()
                .find(|row| row.get("id") == Some(&FieldValue::from("B")))
        })
        .ok_or_else(|| AuthError::internal("Missing expected Team peer storage"))?;
    let _ = row.insert(
        if matches!(storage, Storage::Memory(_)) {
            "memberCount"
        } else {
            "member_count"
        }
        .into(),
        7.0.into(),
    );
    assert_eq!(storage.snapshot(TABLES).await?, expected);
    Ok(())
}

async fn memory(joins: bool) -> AuthResult<()> {
    let raw = EphemeralStore::default();
    let store: Arc<dyn AuthStore<StatelessSchema>> = Arc::new(raw.clone());
    tokio::time::timeout(
        Duration::from_secs(10),
        check(store, Storage::Memory(Box::new(raw)), joins),
    )
    .await
    .map_err(|_| AuthError::internal("Retained Team projection contract timed out"))?
}

async fn sql(joins: bool) -> AuthResult<()> {
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
        check(store, Storage::Sqlite(database), joins),
    )
    .await
    .map_err(|_| AuthError::internal("Retained Team projection contract timed out"))?
}

#[tokio::test]
async fn memory_native_team_parent_error_retains_live_peer() -> AuthResult<()> {
    memory(true).await
}
#[tokio::test]
async fn memory_fallback_team_parent_error_retains_live_peer() -> AuthResult<()> {
    memory(false).await
}
#[tokio::test]
async fn sqlite_native_team_parent_error_retains_snapshot_peer() -> AuthResult<()> {
    sql(true).await
}
#[tokio::test]
async fn sqlite_fallback_team_parent_error_retains_snapshot_peer() -> AuthResult<()> {
    sql(false).await
}
