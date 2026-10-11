use super::*;
use better_auth::plugins::organization::hooks::{OrganizationHooks, OrganizationTeamEvent};
use better_auth::server_api::EndpointInput;
use better_auth_core::{AuthRecordFields, CreateInvitation, HttpMethod};

#[path = "organization_error_construction.rs"]
mod errors;

async fn endpoint<S: AuthSchema>(
    auth: &BetterAuth<S>,
    token: &str,
    native: bool,
    team: bool,
    denied: bool,
) -> AuthResult<AuthResponse> {
    let headers = std::collections::HashMap::from([
        ("content-type".into(), "application/json".into()),
        ("origin".into(), "http://fields.test".into()),
        (
            "cookie".into(),
            format!(
                "better-auth.session_token={}",
                better_auth_core::utils::cookie_utils::sign_cookie_value(
                    token,
                    auth.config().signing_secret()
                )
            ),
        ),
    ]);
    let (method, path, body, query, suffix) = if team {
        (
            HttpMethod::Post,
            "/organization/update-team",
            Some(
                json!({"teamId":"source-a", "data":{"name":"Updated", "organizationId":if denied {"other"} else {"organization"}}}),
            ),
            None,
            "",
        )
    } else {
        (
            HttpMethod::Get,
            "/organization/get-invitation",
            None,
            Some(json!({"id":"source-a"})),
            "?id=source-a",
        )
    };
    if native {
        auth.call_endpoint(
            method,
            path,
            EndpointInput {
                headers: Some(headers),
                body,
                query,
                ..Default::default()
            },
        )
        .await
    } else {
        auth.handle_request(
            AuthRequest::from_parts(
                method,
                format!("/api/auth{path}"),
                headers,
                body.as_ref().map(serde_json::to_vec).transpose()?,
                query,
            )
            .with_url(
                format!("http://fields.test/api/auth{path}{suffix}")
                    .parse()
                    .map_err(|error| {
                        AuthError::internal(format!("Invalid contract URL: {error}"))
                    })?,
            ),
        )
        .await
    }
}

#[expect(
    clippy::panic_in_result_fn,
    reason = "Contract assertions report mismatches while setup and callback errors propagate"
)]
fn response(
    actual: AuthResult<AuthResponse>,
    native: bool,
    expected: &FieldValue,
    status: u16,
) -> AuthResult<()> {
    let actual = if status == 200 || !native {
        actual?
    } else {
        let error = required(
            actual.err(),
            "Native endpoint must reject the business operation",
        )?;
        assert_eq!(error.status_code()?, status);
        ordered(&error.body_value()?, expected)?;
        error.to_auth_response().into_http_response()?
    };
    assert_eq!(actual.status, status);
    if native && status == 200 {
        ordered(&actual.body.field_value()?, expected)?;
    }
    assert_eq!(
        actual.body.bytes()?,
        serde_json::to_vec(&required(expected.json()?, "Expected response JSON")?)?
    );
    Ok(())
}

async fn invitation<S: AuthSchema>(
    raw: Arc<dyn AuthStore<S>>,
    storage: Storage,
    native: bool,
) -> AuthResult<()> {
    let token = seed_parents(raw.clone()).await?;
    let ids = Ids::default();
    let writer = auth(raw.clone(), ids.clone(), Vec::new()).await?;
    let mut input = CreateInvitation::new(
        "organization",
        "user-a@fields.test",
        "member",
        "user-a",
        date(),
    );
    input.id = Some("source-a".into());
    input.created_at = Some(date());
    let _ = writer.store().create_invitation(input).await?;
    let mut after = storage.snapshot_with_roles(true).await?;
    let events = Events::default();
    let fields = declaration([
        (
            "organizationId",
            UserFieldConfig {
                transform: Some(FieldTransforms {
                    output: Some(UserFieldTransform::new_async({
                        let events = events.clone();
                        let writer = writer.store().clone();
                        move |value| {
                            let events = events.clone();
                            let writer = writer.clone();
                            async move {
                                event(&events, "organizationId", value.clone())?;
                                mutate(writer.as_ref(), Model::Invitation, "source-a").await?;
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
            "expiresAt",
            output_policy(
                Model::Invitation,
                UserFieldTransform::new({
                    let events = events.clone();
                    move |value| {
                        event(&events, "expiresAt", value.clone())?;
                        Ok(value)
                    }
                }),
            ),
        ),
    ]);
    let reader = auth(raw, ids, vec![(EntityRole::Invitation, fields)]).await?;
    let result = endpoint(&reader, &token, native, false, false).await;
    let mut row = visible(Model::Invitation, "source-a", "First");
    let _ = row.insert("organizationId".into(), "organization".into());
    let _ = row.insert("email".into(), "user-a@fields.test".into());
    let expected = if storage.memory() {
        FieldMap::from_iter([("message".into(), "Invitation not found!".into())]).into()
    } else {
        let mut response = row.clone();
        response.extend([
            ("organizationName".into(), "Organization".into()),
            ("organizationSlug".into(), "organization".into()),
            ("inviterEmail".into(), "user-a@fields.test".into()),
        ]);
        response.into()
    };
    response(
        result,
        native,
        &expected,
        if storage.memory() { 400 } else { 200 },
    )?;
    ordered(
        &trace_lock(&events)?.clone().into(),
        &vec![
            FieldValue::from(vec!["organizationId".into(), "organization".into()]),
            FieldValue::from(vec![
                "expiresAt".into(),
                raw_late(
                    &storage,
                    if storage.memory() { past() } else { date() }.into(),
                )?,
            ]),
        ]
        .into(),
    )?;
    let _ = row.insert("expiresAt".into(), past().into());
    replace(
        &mut after,
        Model::Invitation,
        "source-a",
        stored(&storage, &row)?,
    )?;
    assert_eq!(storage.snapshot_with_roles(true).await?, after);
    Ok(())
}

struct Hooks(Events);

fn hook_fields(data: OrganizationTeamEvent<'_>) -> AuthResult<FieldValue> {
    let user = required(
        required(data.user, "Expected actor")?.as_object(),
        "Expected actor object",
    )?;
    Ok(FieldMap::from_iter([
        ("team".into(), data.team.field_values()?.into()),
        ("organizationId".into(), data.organization.id.field_value()),
        (
            "userId".into(),
            required(user.get("id")?, "Expected actor ID")?,
        ),
    ])
    .into())
}

#[async_trait]
impl OrganizationHooks for Hooks {
    async fn before_update_team(
        &self,
        updates: &mut UpdateTeam,
        data: OrganizationTeamEvent<'_>,
    ) -> AuthResult<()> {
        assert_eq!(updates.name, Some("Updated".into()));
        assert!(updates.organization_id.is_none());
        assert!(updates.additional_fields.is_empty());
        event(&self.0, "before", hook_fields(data)?)
    }
    async fn after_update_team(&self, data: OrganizationTeamEvent<'_>) -> AuthResult<()> {
        event(&self.0, "after", hook_fields(data)?)
    }
}

fn team_output(name: &str, org: &str) -> FieldMap {
    let mut row = visible(Model::Team, "source-a", name);
    let _ = row.shift_remove("memberCount");
    let _ = row.insert("organizationId".into(), org.into());
    row
}

fn hook_expected(team: FieldMap) -> FieldValue {
    FieldMap::from_iter([
        ("team".into(), team.into()),
        ("organizationId".into(), "organization".into()),
        ("userId".into(), "user-a".into()),
    ])
    .into()
}

async fn team<S: AuthSchema>(
    raw: Arc<dyn AuthStore<S>>,
    storage: Storage,
    native: bool,
    denied: bool,
) -> AuthResult<()> {
    let token = seed_parents(raw.clone()).await?;
    let ids = Ids::default();
    let writer = auth(raw.clone(), ids.clone(), Vec::new()).await?;
    let _ = writer
        .store()
        .create_team(CreateTeam {
            id: Some("source-a".into()),
            name: "First".into(),
            organization_id: "organization".into(),
            created_at: Some(date()),
            updated_at: Some(date()),
            ..Default::default()
        })
        .await?;
    let mut after = storage.snapshot_with_roles(true).await?;
    let events = Events::default();
    let fields = declaration([
        (
            "name",
            UserFieldConfig {
                transform: Some(FieldTransforms {
                    output: Some(UserFieldTransform::new_async({
                        let events = events.clone();
                        let writer = writer.store().clone();
                        move |value| {
                            let events = events.clone();
                            let writer = writer.clone();
                            async move {
                                event(&events, "name", value.clone())?;
                                if value.as_str() == Some("Updated") {
                                    mutate(writer.as_ref(), Model::Team, "source-a").await?;
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
            "organizationId",
            output_policy(
                Model::Team,
                UserFieldTransform::new({
                    let events = events.clone();
                    move |value| {
                        event(&events, "organizationId", value.clone())?;
                        Ok(value)
                    }
                }),
            ),
        ),
    ]);
    let plugin = OrganizationConfig {
        hooks: Some(Arc::new(Hooks(events.clone()))),
        ..Default::default()
    };
    let reader = auth_config(raw, ids, vec![(EntityRole::Team, fields)], plugin).await?;
    let result = endpoint(&reader, &token, native, true, denied).await;
    if denied {
        response(
            result,
            native,
            &FieldMap::from_iter([
                (
                    "message".into(),
                    "You are not allowed to update this team".into(),
                ),
                (
                    "code".into(),
                    "YOU_ARE_NOT_ALLOWED_TO_UPDATE_THIS_TEAM".into(),
                ),
            ])
            .into(),
            403,
        )?;
        assert!(trace_lock(&events)?.is_empty());
    } else {
        let org = if storage.memory() {
            "other"
        } else {
            "organization"
        };
        let expected = team_output("Updated", org);
        response(result, native, &expected.clone().into(), 200)?;
        ordered(
            &trace_lock(&events)?.clone().into(),
            &vec![
                FieldValue::from(vec!["name".into(), "First".into()]),
                FieldValue::from(vec!["organizationId".into(), "organization".into()]),
                FieldValue::from(vec![
                    "before".into(),
                    hook_expected(team_output("First", "organization")),
                ]),
                FieldValue::from(vec!["name".into(), "Updated".into()]),
                FieldValue::from(vec!["organizationId".into(), org.into()]),
                FieldValue::from(vec!["after".into(), hook_expected(expected)]),
            ]
            .into(),
        )?;
        let mut physical = visible(Model::Team, "source-a", "Updated");
        let _ = physical.insert("organizationId".into(), "other".into());
        replace(
            &mut after,
            Model::Team,
            "source-a",
            stored(&storage, &physical)?,
        )?;
    }
    assert_eq!(storage.snapshot_with_roles(true).await?, after);
    Ok(())
}

#[tokio::test]
async fn invitation_expiry_consumes_the_projected_deadline() -> AuthResult<()> {
    for native in [false, true] {
        let (raw, storage) = memory_fixture();
        invitation(raw, storage, native).await?;
        let (raw, storage) = sqlite_fixture().await?;
        invitation(raw, storage, native).await?;
    }
    Ok(())
}

#[tokio::test]
async fn team_update_consumes_projected_scope_after_authorization() -> AuthResult<()> {
    for native in [false, true] {
        for denied in [false, true] {
            let (raw, storage) = memory_fixture();
            team(raw, storage, native, denied).await?;
            let (raw, storage) = sqlite_fixture().await?;
            team(raw, storage, native, denied).await?;
        }
    }
    Ok(())
}
