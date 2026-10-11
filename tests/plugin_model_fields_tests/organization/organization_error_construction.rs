use super::*;

#[derive(Clone, Copy, Debug)]
enum Case {
    TeamSession,
    SlugSession,
    TeamOrganization,
    MissingTeam,
    CreateSession,
    RemoveSession,
    RemoveOrganization,
    UpdateSession,
    UpdateOrganization,
    InvitationOrganization,
}

impl Case {
    const ALL: [Self; 10] = [
        Self::TeamSession,
        Self::SlugSession,
        Self::TeamOrganization,
        Self::MissingTeam,
        Self::CreateSession,
        Self::RemoveSession,
        Self::RemoveOrganization,
        Self::UpdateSession,
        Self::UpdateOrganization,
        Self::InvitationOrganization,
    ];

    fn authenticated(self) -> bool {
        matches!(
            self,
            Self::TeamOrganization
                | Self::MissingTeam
                | Self::UpdateOrganization
                | Self::InvitationOrganization
        )
    }

    fn request(self) -> (HttpMethod, &'static str, Option<Value>) {
        match self {
            Self::TeamSession | Self::TeamOrganization => (
                HttpMethod::Post,
                "/organization/update-team",
                Some(json!({"teamId":"missing", "data":{"name":"Updated"}})),
            ),
            Self::MissingTeam => (
                HttpMethod::Post,
                "/organization/update-team",
                Some(
                    json!({"teamId":"missing", "data":{"name":"Updated", "organizationId":"organization"}}),
                ),
            ),
            Self::SlugSession => (
                HttpMethod::Post,
                "/organization/check-slug",
                Some(json!({"slug":"available"})),
            ),
            Self::CreateSession => (
                HttpMethod::Post,
                "/organization/create-team",
                Some(json!({"name":"New", "organizationId":"organization"})),
            ),
            Self::RemoveSession => (
                HttpMethod::Post,
                "/organization/remove-team",
                Some(json!({"teamId":"missing", "organizationId":"organization"})),
            ),
            Self::RemoveOrganization => (
                HttpMethod::Post,
                "/organization/remove-team",
                Some(json!({"teamId":"missing"})),
            ),
            Self::UpdateSession | Self::UpdateOrganization => (
                HttpMethod::Post,
                "/organization/update",
                Some(json!({"data":{"name":"Updated"}})),
            ),
            Self::InvitationOrganization => {
                (HttpMethod::Get, "/organization/list-invitations", None)
            }
        }
    }

    fn expected(self) -> (u16, FieldValue) {
        let (status, message, code) = match self {
            Self::TeamSession | Self::SlugSession => (401, "Unauthorized", Some("UNAUTHORIZED")),
            Self::TeamOrganization | Self::RemoveOrganization => (
                400,
                "No active organization",
                Some("NO_ACTIVE_ORGANIZATION"),
            ),
            Self::MissingTeam => (400, "Team not found", Some("TEAM_NOT_FOUND")),
            Self::CreateSession | Self::RemoveSession => return (401, FieldValue::Undefined),
            Self::UpdateSession => (401, "User not found", None),
            Self::UpdateOrganization => (
                400,
                "Organization not found",
                Some("ORGANIZATION_NOT_FOUND"),
            ),
            Self::InvitationOrganization => (400, "Organization ID is required", None),
        };
        let mut body = FieldMap::from([("message".into(), message.into())]);
        if let Some(code) = code {
            let _ = body.insert("code".into(), code.into());
        }
        (status, body.into())
    }
}

#[expect(
    clippy::panic_in_result_fn,
    reason = "The paired contract compares complete errors, callback order, and every stored table"
)]
async fn check<S: AuthSchema>(
    raw: Arc<dyn AuthStore<S>>,
    storage: Storage,
    case: Case,
    native: bool,
) -> AuthResult<()> {
    let token = seed_parents(raw.clone()).await?;
    let _ = raw
        .update_session_active_organization_by_token_value(&token.as_str().into(), None)
        .await?;
    let before = storage.snapshot_with_roles(true).await?;
    let events = Events::default();
    let events_for_field = events.clone();
    let policies = vec![(
        EntityRole::Team,
        declaration([(
            "name",
            UserFieldConfig {
                transform: Some(FieldTransforms {
                    output: Some(UserFieldTransform::new(move |value| {
                        event(&events_for_field, "name", value.clone())?;
                        Ok(value)
                    })),
                    ..Default::default()
                }),
                ..Default::default()
            },
        )]),
    )];
    let reader = auth_config(
        raw,
        Ids::default(),
        policies,
        OrganizationConfig {
            hooks: Some(Arc::new(Hooks(events.clone()))),
            ..Default::default()
        },
    )
    .await?;
    let mut headers = std::collections::HashMap::from([
        ("content-type".into(), "application/json".into()),
        ("origin".into(), "http://fields.test".into()),
    ]);
    if case.authenticated() {
        let _ = headers.insert(
            "cookie".into(),
            format!(
                "better-auth.session_token={}",
                better_auth_core::utils::cookie_utils::sign_cookie_value(
                    &token,
                    reader.config().signing_secret()
                )
            ),
        );
    }
    let (method, path, body) = case.request();
    let result = if native {
        reader
            .call_endpoint(
                method,
                path,
                EndpointInput {
                    headers: Some(headers),
                    body,
                    ..Default::default()
                },
            )
            .await
    } else {
        reader
            .handle_request(
                AuthRequest::from_parts(
                    method,
                    format!("/api/auth{path}"),
                    headers,
                    body.as_ref().map(serde_json::to_vec).transpose()?,
                    None,
                )
                .with_url(
                    format!("http://fields.test/api/auth{path}")
                        .parse()
                        .map_err(|error| {
                            AuthError::internal(format!("Invalid contract URL: {error}"))
                        })?,
                ),
            )
            .await
    };
    let (status, expected) = case.expected();
    let actual = if native {
        let error = required(result.err(), "Native endpoint must reject the operation")?;
        assert!(error.is_api_error());
        assert_eq!(error.status_code(), status, "{case:?}");
        let response = error.to_auth_response();
        ordered(&response.body.field_value()?, &expected)?;
        response.into_http_response()?
    } else {
        result?
    };
    assert_eq!(actual.status, status, "{case:?}");
    let bytes = expected
        .json()?
        .map(|body| serde_json::to_vec(&body))
        .transpose()?
        .unwrap_or_default();
    assert_eq!(actual.body.bytes()?.as_ref(), bytes.as_slice(), "{case:?}");
    assert!(trace_lock(&events)?.is_empty(), "{case:?}");
    assert_eq!(storage.snapshot_with_roles(true).await?, before, "{case:?}");
    Ok(())
}

#[tokio::test]
async fn organization_errors_preserve_constructor_provenance() -> AuthResult<()> {
    for case in Case::ALL {
        for native in [true, false] {
            let (raw, storage) = memory_fixture();
            check(raw, storage, case, native).await?;
            let (raw, storage) = sqlite_fixture().await?;
            check(raw, storage, case, native).await?;
        }
    }
    Ok(())
}
