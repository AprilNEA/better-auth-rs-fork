use super::*;

#[path = "team_transaction_projection_support.rs"]
mod policies;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Scenario {
    AddMismatch,
    AcceptMismatch,
    AddHiddenId,
    AcceptHiddenId,
    AddClone,
    AcceptClone,
    Many,
    SecondClone,
    MemberError,
}

impl Scenario {
    const ALL: [Self; 9] = [
        Self::AddMismatch,
        Self::AcceptMismatch,
        Self::AddHiddenId,
        Self::AcceptHiddenId,
        Self::AddClone,
        Self::AcceptClone,
        Self::Many,
        Self::SecondClone,
        Self::MemberError,
    ];
    fn add(self) -> bool {
        matches!(self, Self::AddMismatch | Self::AddHiddenId | Self::AddClone)
    }
    fn mismatch(self) -> bool {
        matches!(self, Self::AddMismatch | Self::AcceptMismatch)
    }
    fn many(self) -> bool {
        matches!(self, Self::Many | Self::SecondClone)
    }
    fn team_ids(self) -> &'static str {
        if self.many() {
            "team-a,team-b"
        } else {
            "team-a"
        }
    }
    fn success(self) -> bool {
        matches!(self, Self::AddHiddenId | Self::AcceptHiddenId | Self::Many)
    }
    fn clone_at(self, name: Option<&str>) -> bool {
        matches!(self, Self::AddClone | Self::AcceptClone)
            || (self == Self::SecondClone && name == Some("Team B"))
    }
}

#[derive(Clone, Copy, Debug)]
enum Entry {
    Native,
    Http,
}

#[derive(Clone, Copy, Debug)]
struct Run {
    scenario: Scenario,
    entry: Entry,
    joins: bool,
}

fn response(scenario: Scenario) -> FieldValue {
    let member: FieldValue = FieldMap::from_iter([
        ("organizationId".into(), "organization".into()),
        ("userId".into(), "user-b".into()),
        ("role".into(), "member".into()),
        ("createdAt".into(), date(0).into()),
        ("id".into(), "member-a".into()),
    ])
    .into();
    if scenario.add() {
        return member;
    }
    let invitation: FieldValue = FieldMap::from_iter([
        ("organizationId".into(), "organization".into()),
        ("email".into(), "user-b@team-member-fields.test".into()),
        ("role".into(), "member".into()),
        ("teamId".into(), scenario.team_ids().into()),
        ("status".into(), "accepted".into()),
        ("expiresAt".into(), date(30).into()),
        ("createdAt".into(), date(0).into()),
        ("inviterId".into(), "user-a".into()),
        ("id".into(), "invitation-a".into()),
    ])
    .into();
    FieldMap::from_iter([("invitation".into(), invitation), ("member".into(), member)]).into()
}

async fn check<S: AuthSchema>(
    raw: Arc<dyn AuthStore<S>>,
    storage: Storage,
    run: Run,
) -> AuthResult<()> {
    let scenario = run.scenario;
    let token =
        fixture::seed_with_team_ids(raw.as_ref(), Case::Accept, Some(scenario.team_ids())).await?;
    if scenario.mismatch() {
        let _ = raw
            .insert_organization(Organization {
                field_order: Default::default(),
                id: "other".into(),
                name: "Other".into(),
                slug: "other".into(),
                logo: None.into(),
                metadata: Some(FieldValue::from("{}")).into(),
                created_at: date(0).into(),
                additional_fields: Default::default(),
            })
            .await?;
        let _ = raw
            .update_team(
                "team-a",
                UpdateTeam {
                    organization_id: Some("other".into()),
                    ..Default::default()
                },
            )
            .await?;
    }
    let mut before = fixture::snapshot(&storage).await?;
    let events = Events::default();
    let auth = policies::auth(raw, &events, run).await?;
    let headers = std::collections::HashMap::from([
        ("content-type".into(), "application/json".into()),
        ("origin".into(), "http://fields.test".into()),
        (
            "cookie".into(),
            format!(
                "better-auth.session_token={}",
                better_auth_core::utils::cookie_utils::sign_cookie_value(
                    &token,
                    auth.config().signing_secret()
                )
            ),
        ),
    ]);
    assert!(events.take()?.is_empty());
    let result = if scenario.add() {
        auth.organization()?.with_request(better_auth_core::NativeRequest { request: None, headers: Some(&headers) })
            .add_member(Some(json!({"organizationId":"organization", "userId":"user-b", "role":"member", "teamId":"team-a"})))
            .await.and_then(|value| AuthResponse::json(200, &value))
    } else {
        let body = json!({"invitationId":"invitation-a"});
        match run.entry {
            Entry::Native => {
                auth.call_endpoint(
                    HttpMethod::Post,
                    "/organization/accept-invitation",
                    EndpointInput {
                        headers: Some(headers),
                        body: Some(body),
                        ..Default::default()
                    },
                )
                .await
            }
            Entry::Http => {
                auth.handle_request(
                    AuthRequest::from_parts(
                        HttpMethod::Post,
                        "/api/auth/organization/accept-invitation".into(),
                        headers,
                        Some(serde_json::to_vec(&body)?),
                        None,
                    )
                    .with_url(
                        "http://fields.test/api/auth/organization/accept-invitation"
                            .parse()
                            .map_err(|error| {
                                AuthError::internal(format!("Invalid acceptance URL: {error}"))
                            })?,
                    ),
                )
                .await
            }
        }
    };
    if scenario.success() {
        let actual = result?;
        assert_eq!(actual.status, 200, "{run:?}");
        let expected = response(scenario);
        if scenario.add() || matches!(run.entry, Entry::Http) {
            assert_eq!(
                actual.body.bytes()?,
                serde_json::to_vec(&required(
                    expected.json()?,
                    "Expected complete JSON response"
                )?)?,
                "{run:?}"
            );
        } else {
            assert_ordered(&actual.body.field_value()?, &expected)?;
        }
    } else if matches!(run.entry, Entry::Native) {
        let error = result
            .err()
            .ok_or_else(|| AuthError::internal("Expected Team transaction failure"))?;
        if scenario.mismatch() {
            assert_eq!(error.status_code()?, 400, "{run:?}");
            assert_eq!(
                error.body_value()?.json()?,
                Some(json!({"code":"TEAM_NOT_FOUND", "message":"Team not found"})),
                "{run:?}"
            );
        } else if scenario == Scenario::MemberError {
            assert!(
                matches!(error, AuthError::Internal(ref message) if message == "member-create-failed"),
                "{run:?}: {error:?}"
            );
        } else {
            assert!(matches!(error, AuthError::DataClone), "{run:?}: {error:?}");
            assert_eq!(error.to_string(), "The object can not be cloned.");
        }
    } else {
        let actual = result?;
        if scenario.mismatch() {
            assert_eq!(actual.status, 400, "{run:?}");
            assert_eq!(
                actual.body.json()?,
                Some(json!({"code":"TEAM_NOT_FOUND", "message":"Team not found"})),
                "{run:?}"
            );
        } else {
            assert_eq!(actual.status, 500, "{run:?}");
            assert!(actual.body.bytes()?.is_empty(), "{run:?}");
        }
    }
    assert_eq!(
        events.take()?,
        policies::expected_events(&storage, scenario),
        "{run:?}"
    );
    policies::update_snapshot(&storage, scenario, &mut before)?;
    assert_eq!(fixture::snapshot(&storage).await?, before, "{run:?}");
    Ok(())
}

#[tokio::test]
async fn memory_team_transaction_projection_preserves_scope_order_and_rollback() -> AuthResult<()> {
    for scenario in Scenario::ALL {
        for entry in [Entry::Native, Entry::Http]
            .into_iter()
            .filter(|entry| !scenario.add() || matches!(entry, Entry::Native))
        {
            for joins in [false, true] {
                let store = EphemeralStore::new(Arc::new(config()));
                let raw: Arc<dyn AuthStore<StatelessSchema>> = Arc::new(store.clone());
                check(
                    raw,
                    Storage::Memory(Box::new(store)),
                    Run {
                        scenario,
                        entry,
                        joins,
                    },
                )
                .await?;
            }
        }
    }
    Ok(())
}

#[tokio::test]
async fn sqlite_team_transaction_projection_preserves_scope_order_and_rollback() -> AuthResult<()> {
    for scenario in Scenario::ALL {
        for entry in [Entry::Native, Entry::Http]
            .into_iter()
            .filter(|entry| !scenario.add() || matches!(entry, Entry::Native))
        {
            for joins in [false, true] {
                let mut options = ConnectOptions::new("sqlite::memory:");
                let _ = options.max_connections(1);
                let database = Database::connect(options)
                    .await
                    .map_err(|error| AuthError::internal(error.to_string()))?;
                migrator::run_migrations(&database)
                    .await
                    .map_err(|error| AuthError::internal(error.to_string()))?;
                let raw: Arc<dyn AuthStore<BundledSchema>> = Arc::new(
                    SeaOrmStore::<BundledSchema>::new(config(), database.clone()),
                );
                check(
                    raw,
                    Storage::Sqlite(database),
                    Run {
                        scenario,
                        entry,
                        joins,
                    },
                )
                .await?;
            }
        }
    }
    Ok(())
}
