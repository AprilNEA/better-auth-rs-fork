#![expect(
    clippy::panic_in_result_fn,
    reason = "Assertions report callback and storage regressions; fixture setup errors propagate through Result."
)]

use super::rows::RowRef;
use super::*;
use crate::id::IdGeneration;
use crate::organization_fields::OrganizationFields;
use crate::store::{TeamMemberLimitResolver, TeamMemberLimits};
use crate::user_fields::{
    FieldTransforms, UserConfig, UserFieldConfig, UserFieldTransform, UserFieldType,
};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

type Events = Arc<Mutex<Vec<(&'static str, Value)>>>;

fn required<T>(value: Option<T>) -> AuthResult<T> {
    value.ok_or_else(|| AuthError::internal("Expected a stored invitation fixture row"))
}

fn events_snapshot(events: &Events) -> AuthResult<Vec<(&'static str, Value)>> {
    events
        .lock()
        .map_err(|_| AuthError::internal("Event lock poisoned"))
        .map(|events| events.clone())
}

fn event(events: &Events, name: &'static str, value: Value) -> AuthResult<()> {
    events
        .lock()
        .map_err(|_| AuthError::internal("Event lock poisoned"))?
        .push((name, value));
    Ok(())
}

fn seed_team(
    store: &EphemeralStore,
    id: Value,
    name: &str,
    organization: Value,
    count: f64,
) -> AuthResult<RowRef<FieldMap>> {
    Ok(store.lock()?.teams.push_ref(
        [
            ("id".into(), id),
            ("name".into(), name.into()),
            ("organizationId".into(), organization),
            ("createdAt".into(), Utc::now().into()),
            ("memberCount".into(), Value::Number(count)),
        ]
        .into(),
    ))
}

fn membership(id: Value, team: Value, user: &str) -> FieldMap {
    [
        ("id".into(), id),
        ("teamId".into(), team),
        ("userId".into(), user.into()),
        ("membershipKey".into(), user.into()),
        ("createdAt".into(), Utc::now().into()),
    ]
    .into()
}

async fn invitation(
    store: &EphemeralStore,
    organization: &str,
    teams: &str,
) -> AuthResult<Invitation> {
    let mut input = CreateInvitation::new(
        organization,
        "recipient@example.com",
        "member",
        "9",
        (Utc::now() + chrono::Duration::days(1)).into(),
    );
    input.team_id = Some(teams.into());
    store.create_invitation(input).await
}

struct ProjectionLimits {
    calls: AtomicUsize,
    events: Events,
    fields: UserConfig,
}

#[async_trait]
impl TeamMemberLimitResolver for ProjectionLimits {
    fn team_output_fields(&self) -> Option<&UserConfig> {
        Some(&self.fields)
    }

    async fn maximum(&self, team_id: &str, _: &Value) -> AuthResult<Option<usize>> {
        event(&self.events, "maximum", team_id.into())?;
        Ok(Some(if self.calls.fetch_add(1, Ordering::SeqCst) == 2 {
            0
        } else {
            1
        }))
    }
}

#[tokio::test]
async fn acceptance_reads_live_teams_and_pending_seats_without_callback_replay() -> AuthResult<()> {
    for serial in [false, true] {
        for outcome in ["commit", "reject", "conflict"] {
            let mut config = (*test_config()).clone();
            if serial {
                config.advanced.database.generate_id = Some(IdGeneration::Serial);
            }
            let store = EphemeralStore::new(Arc::new(config));
            let (organization, user, first_selector, second_selector, duplicate) = if serial {
                ("1", "3", "01", "02", "1")
            } else {
                ("organization", "recipient", "first", "second", "first")
            };
            let owner = if serial {
                Value::Number(1.0)
            } else {
                organization.into()
            };
            let first = seed_team(
                &store,
                if serial {
                    Value::Number(1.0)
                } else {
                    "first".into()
                },
                "First",
                owner.clone(),
                0.0,
            )?;
            let second = seed_team(
                &store,
                if serial {
                    Value::Number(2.0)
                } else {
                    "second".into()
                },
                "Second",
                "other".into(),
                0.0,
            )?;
            let claimed = invitation(
                &store,
                organization,
                &format!("{first_selector},{second_selector},{duplicate}"),
            )
            .await?;
            let original_teams = store.lock()?.teams.snapshot()?;
            let events = Events::default();
            let mut fields = OrganizationFields::default();
            let _ = fields.team.fields_mut().insert(
                "name".into(),
                UserFieldConfig {
                    transform: Some(FieldTransforms {
                        output: Some(UserFieldTransform::new({
                            let events = events.clone();
                            let second = second.clone();
                            let owner = owner.clone();
                            let changed = AtomicBool::new(false);
                            move |value| {
                                event(&events, "team.name", value.clone())?;
                                if !changed.swap(true, Ordering::SeqCst) {
                                    second.write(|row| {
                                        let _ = row.insert("name".into(), "Second live".into());
                                        let _ = row.insert("organizationId".into(), owner.clone());
                                        Ok(())
                                    })?;
                                }
                                Ok(value)
                            }
                        })),
                        ..Default::default()
                    }),
                    ..Default::default()
                },
            );
            let _ = fields.team.fields_mut().insert(
                "memberCount".into(),
                UserFieldConfig {
                    field_type: UserFieldType::Number,
                    transform: Some(FieldTransforms {
                        output: Some(UserFieldTransform::new({
                            let events = events.clone();
                            move |value| {
                                event(&events, "team.count", value.clone())?;
                                Ok(value)
                            }
                        })),
                        ..Default::default()
                    }),
                    ..Default::default()
                },
            );
            let _ = fields.member.fields_mut().insert(
                "role".into(),
                UserFieldConfig {
                    transform: Some(FieldTransforms {
                        input: Some(UserFieldTransform::new({
                            let events = events.clone();
                            let first = first.clone();
                            move |value| {
                                event(&events, "member.input", value.clone())?;
                                if outcome == "reject" {
                                    return Err(AuthError::type_error("member-rejected"));
                                }
                                if outcome == "conflict" {
                                    first.write(|row| {
                                        let _ =
                                            row.insert("memberCount".into(), Value::Number(9.0));
                                        Ok(())
                                    })?;
                                }
                                Ok(value)
                            }
                        })),
                        output: Some(UserFieldTransform::new({
                            let events = events.clone();
                            move |value| {
                                event(&events, "member.output", value.clone())?;
                                Ok(value)
                            }
                        })),
                    }),
                    ..Default::default()
                },
            );
            let _ = fields.invitation.fields_mut().insert(
                "status".into(),
                UserFieldConfig {
                    transform: Some(FieldTransforms {
                        output: Some(UserFieldTransform::new({
                            let events = events.clone();
                            move |value| {
                                event(&events, "invitation", value.clone())?;
                                Ok(value)
                            }
                        })),
                        ..Default::default()
                    }),
                    ..Default::default()
                },
            );
            let limits = ProjectionLimits {
                calls: AtomicUsize::new(0),
                events: events.clone(),
                fields: fields.team.clone(),
            };
            store.configure_organization_fields(fields)?;
            let result = store
                .accept_invitation_with_teams(
                    claimed.id.typed()?,
                    user,
                    None,
                    true,
                    TeamMemberLimits::Resolver(&limits),
                )
                .await;
            match outcome {
                "commit" => {
                    let _ = result?;
                }
                "reject" => assert!(
                    matches!(result, Err(AuthError::TypeError(message)) if message == "member-rejected")
                ),
                _ => assert!(matches!(result, Err(AuthError::Conflict(_)))),
            }
            let mut expected = vec![
                ("invitation", "accepted".into()),
                ("team.name", "First".into()),
                ("team.count", Value::Number(0.0)),
                ("maximum", first_selector.into()),
                ("team.name", "First".into()),
                ("team.count", Value::Number(1.0)),
                ("team.name", "Second live".into()),
                ("team.count", Value::Number(0.0)),
                ("maximum", second_selector.into()),
                ("team.name", "Second live".into()),
                ("team.count", Value::Number(1.0)),
                ("team.name", "First".into()),
                ("team.count", Value::Number(1.0)),
                ("maximum", duplicate.into()),
                ("member.input", "member".into()),
            ];
            if outcome != "reject" {
                expected.push(("member.output", "member".into()));
            }
            if outcome != "commit" {
                expected.push(("invitation", "pending".into()));
            }
            assert_eq!(
                events_snapshot(&events)?,
                expected,
                "{outcome}, serial={serial}"
            );
            assert_eq!(limits.calls.load(Ordering::SeqCst), 3);
            let mut expected_teams = original_teams;
            let second = required(expected_teams.get_mut(1))?;
            let _ = second.insert("name".into(), "Second live".into());
            let _ = second.insert("organizationId".into(), owner);
            if outcome == "commit" {
                for row in &mut expected_teams {
                    let _ = row.insert("memberCount".into(), Value::Number(1.0));
                }
            } else if outcome == "conflict" {
                let _ = required(expected_teams.first_mut())?
                    .insert("memberCount".into(), Value::Number(9.0));
            }
            let state = store.lock()?;
            assert_eq!(state.teams.snapshot()?, expected_teams);
            assert_eq!(state.members.len(), usize::from(outcome == "commit"));
            assert_eq!(
                state.team_members.len(),
                if outcome == "commit" { 2 } else { 0 }
            );
            let rows = state.invitations.snapshot()?;
            assert_eq!(
                required(rows.first())?.get("status"),
                Some(&Value::from(if outcome == "commit" {
                    "accepted"
                } else {
                    "pending"
                }))
            );
        }
    }
    Ok(())
}

#[tokio::test]
async fn pending_team_scope_patch_is_used_by_the_next_scoped_lookup() -> AuthResult<()> {
    let store = EphemeralStore::new(test_config());
    let _ = seed_team(&store, "first".into(), "First", "organization".into(), -1.0)?;
    let claimed = invitation(&store, "organization", "first,first").await?;
    let original = store.lock()?.teams.snapshot()?;
    let events = Events::default();
    let mut fields = OrganizationFields::default();
    let _ = fields.team.fields_mut().insert(
        "organizationId".into(),
        UserFieldConfig {
            on_update: Some(Arc::new(|| Ok("other".into()))),
            ..Default::default()
        },
    );
    let _ = fields.team.fields_mut().insert(
        "memberCount".into(),
        UserFieldConfig {
            field_type: UserFieldType::Number,
            transform: Some(FieldTransforms {
                output: Some(UserFieldTransform::new({
                    let events = events.clone();
                    move |value| {
                        event(&events, "count", value.clone())?;
                        Ok(value)
                    }
                })),
                ..Default::default()
            }),
            ..Default::default()
        },
    );
    let limits = ProjectionLimits {
        calls: AtomicUsize::new(0),
        events: events.clone(),
        fields: fields.team.clone(),
    };
    store.configure_organization_fields(fields)?;
    let result = store
        .accept_invitation_with_teams(
            claimed.id.typed()?,
            "recipient",
            None,
            true,
            TeamMemberLimits::Resolver(&limits),
        )
        .await;
    assert!(matches!(result, Err(AuthError::BadRequest(message)) if message == "Team not found"));
    assert_eq!(
        events_snapshot(&events)?,
        vec![
            ("count", Value::Number(-1.0)),
            ("maximum", "first".into()),
            ("count", Value::Number(0.0)),
            ("count", Value::Number(1.0))
        ]
    );
    let state = store.lock()?;
    assert_eq!(state.teams.snapshot()?, original);
    assert_eq!(state.team_members.len(), 0);
    assert_eq!(state.members.len(), 0);
    assert_eq!(
        required(state.invitations.snapshot()?.first())?.get("status"),
        Some(&Value::from("pending"))
    );
    Ok(())
}

struct ConcurrentMembershipLimits {
    store: EphemeralStore,
    calls: AtomicUsize,
    serial: bool,
    concurrent: FieldMap,
}

#[async_trait]
impl TeamMemberLimitResolver for ConcurrentMembershipLimits {
    async fn maximum(&self, _: &str, _: &Value) -> AuthResult<Option<usize>> {
        let call = self.calls.fetch_add(1, Ordering::SeqCst);
        let mut state = self.store.lock()?;
        if self.serial && call == 1 {
            let _ = state
                .team_members
                .remove_first(|row| row.get("id") == Some(&Value::Number(1.0)))?;
            state.team_members.push(self.concurrent.clone());
        } else if !self.serial {
            if call == 0 {
                state.team_members.push(self.concurrent.clone());
            } else {
                let _ = state
                    .team_members
                    .remove_first(|row| row.get("id") == Some(&Value::from("external")))?;
            }
        }
        Ok(Some(1))
    }
}

#[tokio::test]
async fn membership_refresh_preserves_external_deletion_and_serial_allocation() -> AuthResult<()> {
    for serial in [false, true] {
        let mut config = (*test_config()).clone();
        if serial {
            config.advanced.database.generate_id = Some(IdGeneration::Serial);
        }
        let store = EphemeralStore::new(Arc::new(config));
        let (organization, teams, user) = if serial {
            ("1", "1,2", "3")
        } else {
            ("organization", "first,second", "recipient")
        };
        let owner = if serial {
            Value::Number(1.0)
        } else {
            organization.into()
        };
        let _ = seed_team(
            &store,
            if serial {
                Value::Number(1.0)
            } else {
                "first".into()
            },
            "First",
            owner.clone(),
            0.0,
        )?;
        let _ = seed_team(
            &store,
            if serial {
                Value::Number(2.0)
            } else {
                "second".into()
            },
            "Second",
            owner,
            0.0,
        )?;
        if serial {
            store.lock()?.team_members.push(membership(
                Value::Number(1.0),
                Value::Number(9.0),
                "previous",
            ));
        }
        let concurrent = membership(
            if serial {
                Value::Number(2.0)
            } else {
                "external".into()
            },
            if serial {
                Value::Number(9.0)
            } else {
                "outside".into()
            },
            "external",
        );
        let limits = ConcurrentMembershipLimits {
            store: store.clone(),
            calls: AtomicUsize::new(0),
            serial,
            concurrent: concurrent.clone(),
        };
        let claimed = invitation(&store, organization, teams).await?;
        let result = store
            .accept_invitation_with_teams(
                claimed.id.typed()?,
                user,
                None,
                true,
                TeamMemberLimits::Resolver(&limits),
            )
            .await;
        if serial {
            assert!(matches!(result, Err(AuthError::Conflict(_))));
        } else {
            let _ = result?;
        }
        assert_eq!(limits.calls.load(Ordering::SeqCst), 2);
        let state = store.lock()?;
        let memberships = state.team_members.snapshot()?;
        if serial {
            assert_eq!(memberships, vec![concurrent]);
        } else {
            assert_eq!(memberships.len(), 2);
            assert!(
                memberships
                    .iter()
                    .all(|row| row.get("userId") == Some(&Value::from(user)))
            );
        }
        assert_eq!(state.members.len(), usize::from(!serial));
        for team in state.teams.snapshot()? {
            assert_eq!(
                team.get("memberCount"),
                Some(&Value::Number(if serial { 0.0 } else { 1.0 }))
            );
        }
        assert_eq!(
            required(state.invitations.snapshot()?.first())?.get("status"),
            Some(&Value::from(if serial { "pending" } else { "accepted" }))
        );
    }
    Ok(())
}
