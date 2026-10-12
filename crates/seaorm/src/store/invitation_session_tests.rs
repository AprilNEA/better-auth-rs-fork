#![expect(
    clippy::panic_in_result_fn,
    reason = "Assertions verify transaction ordering and stored rows; database errors propagate through Result."
)]

use super::{
    SeaOrmStore,
    bundled_schema::BundledSchema,
    entities::{invitation, member, session, team, team_member, user},
    map_db_err,
};
use crate::hooks::{DatabaseHookUpdate, SeaOrmHookContext, SeaOrmHooks, SessionUpdate};
use better_auth_core::{
    AuthError, AuthResult, CreateInvitation, CreateSession, CreateTeam, FieldMap, FieldValue,
    FromFieldMap, Invitation, Team,
    store::{
        InvitationStore, SessionStore, SessionUpdateWriterFactory, SessionWriteEffects, TeamStore,
    },
    user_fields::{FieldTransforms, UserFieldConfig, UserFieldTransform, UserFieldType},
    wire::{SessionView, UserView},
};
use sea_orm::{ColumnTrait, EntityTrait, QueryFilter};
use std::sync::{Arc, Mutex};

type Events = Arc<Mutex<Vec<String>>>;

fn record(events: &Events, event: impl Into<String>) -> AuthResult<()> {
    events
        .lock()
        .map_err(|_| AuthError::internal("Event lock poisoned"))?
        .push(event.into());
    Ok(())
}

fn required<T>(value: Option<T>) -> AuthResult<T> {
    value.ok_or_else(|| AuthError::internal("Expected an invitation Session fixture value"))
}

struct Fixture {
    store: SeaOrmStore<BundledSchema>,
    team: Team,
    invitation: Invitation,
    session: SessionView,
    original: session::Model,
}

async fn fixture() -> AuthResult<Fixture> {
    let mut store = super::organization_extension_tests::store().await;
    let team = store
        .create_team(CreateTeam {
            id: Some("invited-team".into()),
            name: "Invited team".into(),
            organization_id: "org-a".into(),
            ..Default::default()
        })
        .await?;
    let session = store
        .create_session(CreateSession {
            inherited_fields: Default::default(),
            additional_fields: Default::default(),
            user_id: "user-b".into(),
            expires_at: (chrono::Utc::now() + chrono::Duration::hours(1)).into(),
            ip_address: Some("initial".into()),
            user_agent: Some("initial-agent".into()),
            impersonated_by: None,
            active_organization_id: Some("org-b".into()),
        })
        .await?;
    let original = required(
        session::Entity::find_by_id(session.id.typed()?.clone())
            .one(store.connection())
            .await
            .map_err(map_db_err)?,
    )?;
    let updated_at = original.updated_at;
    let _ = Arc::make_mut(&mut store.config)
        .session
        .fields_mut()
        .insert(
            "updatedAt".into(),
            UserFieldConfig {
                field_type: UserFieldType::Date,
                on_update: Some(better_auth_core::user_fields::UserFieldFactory::new(
                    move || Ok(updated_at.into()),
                )),
                ..Default::default()
            },
        );
    let mut input = CreateInvitation::new(
        "org-a",
        "user-b@example.com",
        "member",
        "user-a",
        (chrono::Utc::now() + chrono::Duration::hours(1)).into(),
    );
    input.team_id = Some(team.id.typed()?.clone());
    let invitation = store.create_invitation(input).await?;
    Ok(Fixture {
        store,
        team,
        invitation,
        session,
        original,
    })
}

struct ObserveSession {
    events: Events,
    mode: &'static str,
}

#[better_auth_core::database_hooks()]
impl SeaOrmHooks<BundledSchema> for ObserveSession {
    async fn before_update_session(
        &self,
        fields: &mut FieldMap,
        context: &SeaOrmHookContext<'_, BundledSchema>,
    ) -> AuthResult<DatabaseHookUpdate<FieldMap>> {
        let phase = if fields.contains_key("activeTeamId") {
            "team"
        } else if fields.contains_key("activeOrganizationId") {
            "organization"
        } else {
            "cookie"
        };
        record(&self.events, format!("before:{phase}"))?;
        let transaction = required(context.transaction)?;
        let connection = required(context.tx)?;
        assert_eq!(
            transaction
                .count_organization_members_value(&"org-a".into())
                .await?,
            i64::from(phase == "organization")
        );
        let team = required(
            team::Entity::find_by_id("invited-team")
                .one(connection)
                .await
                .map_err(map_db_err)?,
        )?;
        assert_eq!(team.member_count, 1);
        assert_eq!(
            team_member::Entity::find()
                .all(connection)
                .await
                .map_err(map_db_err)?
                .len(),
            1
        );
        if phase == "team" {
            let _ = required(
                transaction
                    .create_user_fields_optional(
                        [
                            ("name".into(), "Created by Session hook".into()),
                            ("email".into(), "hook@example.com".into()),
                        ]
                        .into(),
                    )
                    .await?,
            )?;
        }
        if self.mode == "before" && phase == "organization" {
            return Err(AuthError::type_error("before-session"));
        }
        if (self.mode == "cancel-team" && phase == "team")
            || (self.mode == "cancel-organization" && phase == "organization")
        {
            return Ok(DatabaseHookUpdate::Cancel);
        }
        Ok(if phase == "cookie" {
            DatabaseHookUpdate::Continue
        } else {
            DatabaseHookUpdate::Patch([("ipAddress".into(), phase.into())].into())
        })
    }

    async fn after_create_user(
        &self,
        user: Option<&UserView>,
        context: &SeaOrmHookContext<'_, BundledSchema>,
    ) -> AuthResult<()> {
        assert!(context.transaction.is_none());
        assert!(context.tx.is_none());
        assert_eq!(
            required(user)?.email.field_value(),
            "hook@example.com".into()
        );
        assert_eq!(
            member::Entity::find()
                .all(context.db)
                .await
                .map_err(map_db_err)?
                .len(),
            1
        );
        record(&self.events, "after:user")
    }

    async fn after_update_session(
        &self,
        session: Option<&SessionView>,
        context: &SeaOrmHookContext<'_, BundledSchema>,
    ) -> AuthResult<()> {
        assert!(context.transaction.is_none());
        assert!(context.tx.is_none());
        assert_eq!(
            member::Entity::find()
                .all(context.db)
                .await
                .map_err(map_db_err)?
                .len(),
            1
        );
        assert_eq!(
            team_member::Entity::find()
                .all(context.db)
                .await
                .map_err(map_db_err)?
                .len(),
            1
        );
        assert_eq!(
            required(
                invitation::Entity::find()
                    .one(context.db)
                    .await
                    .map_err(map_db_err)?
            )?
            .status,
            "accepted"
        );
        let session = required(session)?;
        let phase = if session.active_organization_id.field_value() == FieldValue::from("org-a") {
            "organization"
        } else if session.user_agent.field_value() == FieldValue::from("cookie-agent") {
            "cookie"
        } else {
            "team"
        };
        record(&self.events, format!("after:{phase}"))?;
        if self.mode == "after" {
            return Err(AuthError::type_error("after-session"));
        }
        Ok(())
    }
}

#[tokio::test]
async fn invitation_session_effects_share_sql_hooks_and_commit_boundaries() -> AuthResult<()> {
    for mode in [
        "commit",
        "before",
        "output",
        "effect",
        "after",
        "cancel-team",
        "cancel-organization",
    ] {
        let Fixture {
            mut store,
            team,
            invitation,
            session,
            original,
        } = fixture().await?;
        let events = Events::default();
        let _ = Arc::make_mut(&mut store.config)
            .session
            .fields_mut()
            .insert(
                "ipAddress".into(),
                UserFieldConfig {
                    transform: Some(FieldTransforms {
                        output: Some(UserFieldTransform::new({
                            let events = events.clone();
                            move |value| {
                                let phase = required(value.as_str())?;
                                record(&events, format!("output:{phase}"))?;
                                if mode == "output" && phase == "organization" {
                                    return Err(AuthError::type_error("output-session"));
                                }
                                Ok(format!("{phase}:projected").into())
                            }
                        })),
                        ..Default::default()
                    }),
                    ..Default::default()
                },
            );
        store = store.hook(ObserveSession {
            events: events.clone(),
            mode,
        });
        let effects = SessionWriteEffects {
            secondary: None,
            after_output: Some(Box::new({
                let events = events.clone();
                move |session, transaction| {
                    Box::pin(async move {
                        record(&events, "effect")?;
                        assert_eq!(
                            session.ip_address.field_value(),
                            FieldValue::from("team:projected")
                        );
                        assert_eq!(
                            session.active_organization_id.field_value(),
                            FieldValue::from("org-b")
                        );
                        assert_eq!(
                            transaction
                                .count_organization_members_value(&"org-a".into())
                                .await?,
                            0
                        );
                        let updated = required(
                            transaction
                                .update_session_with_writer_by_token_value(
                                    &session.token.field_value(),
                                    SessionUpdate {
                                        user_agent: Some(Some("cookie-agent".into())),
                                        ..Default::default()
                                    },
                                    None,
                                )
                                .await?,
                        )?;
                        assert_eq!(
                            updated.user_agent.field_value(),
                            FieldValue::from("cookie-agent")
                        );
                        if mode == "effect" {
                            return Err(AuthError::type_error("effect-session"));
                        }
                        Ok(())
                    })
                }
            })),
        };
        let result = store
            .accept_invitation_with_session_effects_values(
                &invitation.id.field_value(),
                &"user-b".into(),
                Some(&session.token.field_value()),
                true,
                Some(1).into(),
                effects,
            )
            .await;
        let committed = matches!(mode, "commit" | "after" | "cancel-organization");
        if matches!(mode, "commit" | "cancel-organization") {
            let (member, accepted, cookie) = result?;
            assert_eq!(member.organization_id, "org-a");
            assert_eq!(
                accepted.status,
                better_auth_core::InvitationStatus::Accepted
            );
            let cookie = required(cookie)?;
            assert_eq!(
                cookie.ip_address.field_value(),
                FieldValue::from("team:projected")
            );
            assert_eq!(
                cookie.user_agent.field_value(),
                FieldValue::from("initial-agent")
            );
            assert_eq!(
                cookie.active_organization_id.field_value(),
                FieldValue::from("org-b")
            );
            assert_eq!(cookie.active_team_id.field_value(), team.id.field_value());
        } else if mode == "cancel-team" {
            assert!(
                matches!(result, Err(AuthError::TypeError(message)) if message == "Cannot read properties of null (reading 'token')")
            );
        } else {
            assert!(
                matches!(result, Err(AuthError::TypeError(message)) if message == format!("{mode}-session"))
            );
        }
        let mut expected = vec!["before:team"];
        if mode != "cancel-team" {
            expected.extend(["output:team", "effect", "before:cookie", "output:team"]);
            if mode != "effect" {
                expected.push("before:organization");
                if !matches!(mode, "before" | "cancel-organization") {
                    expected.push("output:organization");
                }
            }
        }
        if committed {
            expected.extend(["after:user", "after:team"]);
            if mode != "after" {
                expected.push("after:cookie");
                if mode == "commit" {
                    expected.push("after:organization");
                }
            }
        }
        assert_eq!(
            *events
                .lock()
                .map_err(|_| AuthError::internal("Event lock poisoned"))?,
            expected,
            "{mode}"
        );
        let db = store.connection();
        assert_eq!(
            member::Entity::find()
                .all(db)
                .await
                .map_err(map_db_err)?
                .len(),
            usize::from(committed),
            "{mode}"
        );
        assert_eq!(
            team_member::Entity::find()
                .all(db)
                .await
                .map_err(map_db_err)?
                .len(),
            usize::from(committed),
            "{mode}"
        );
        assert_eq!(
            user::Entity::find()
                .all(db)
                .await
                .map_err(map_db_err)?
                .len(),
            2 + usize::from(committed),
            "{mode}"
        );
        assert_eq!(
            required(
                team::Entity::find_by_id(team.id.typed()?.clone())
                    .one(db)
                    .await
                    .map_err(map_db_err)?
            )?
            .member_count,
            i64::from(committed),
            "{mode}"
        );
        assert_eq!(
            required(
                invitation::Entity::find_by_id(invitation.id.typed()?.clone())
                    .one(db)
                    .await
                    .map_err(map_db_err)?
            )?
            .status,
            if matches!(mode, "commit" | "cancel-organization") {
                "accepted"
            } else {
                "pending"
            },
            "{mode}"
        );
        let mut expected = original;
        if committed {
            expected.active_team_id = Some(team.id.typed()?.clone());
            expected.user_agent = Some("cookie-agent".into());
            expected.ip_address = Some(
                if mode == "cancel-organization" {
                    "team"
                } else {
                    "organization"
                }
                .into(),
            );
            if mode != "cancel-organization" {
                expected.active_organization_id = Some("org-a".into());
            }
        }
        assert_eq!(
            required(
                session::Entity::find_by_id(session.id.typed()?.clone())
                    .one(db)
                    .await
                    .map_err(map_db_err)?
            )?,
            expected,
            "{mode}"
        );
    }
    Ok(())
}

#[tokio::test]
async fn invitation_secondary_writes_keep_external_effects_when_sql_rolls_back() -> AuthResult<()> {
    for write_database in [false, true] {
        for reject in [false, true] {
            let Fixture {
                store,
                team,
                invitation,
                session,
                original,
            } = fixture().await?;
            let mut initial = FieldMap::from(session.clone());
            let _ = initial.insert("ipAddress".into(), "cached".into());
            let cached = Arc::new(Mutex::new(initial.clone()));
            let events = Events::default();
            if !write_database {
                let _ = session::Entity::delete_many()
                    .filter(session::Column::Id.eq(session.id.typed()?.clone()))
                    .exec(store.connection())
                    .await
                    .map_err(map_db_err)?;
            }
            let effects = SessionWriteEffects {
                secondary: Some(SessionUpdateWriterFactory {
                    write_database,
                    write: Arc::new({
                        let cached = cached.clone();
                        let events = events.clone();
                        let token = session.token.field_value();
                        move |actual, fields| {
                            let cached = cached.clone();
                            let events = events.clone();
                            let token = token.clone();
                            Box::pin(async move {
                                assert_eq!(actual, token);
                                record(
                                    &events,
                                    if fields.contains_key("activeTeamId") {
                                        "secondary:team"
                                    } else {
                                        "secondary:organization"
                                    },
                                )?;
                                let mut cached = cached.lock().map_err(|_| {
                                    AuthError::internal("Cache fixture lock poisoned")
                                })?;
                                cached.extend(fields);
                                SessionView::from_field_values(cached.clone()).map(Some)
                            })
                        }
                    }),
                }),
                after_output: Some(Box::new({
                    let events = events.clone();
                    move |session, transaction| {
                        Box::pin(async move {
                            record(&events, "effect")?;
                            assert_eq!(
                                session.ip_address.field_value(),
                                FieldValue::from(if write_database { "initial" } else { "cached" })
                            );
                            assert_eq!(
                                session.active_organization_id.field_value(),
                                FieldValue::from("org-b")
                            );
                            assert_eq!(
                                transaction
                                    .count_organization_members_value(&"org-a".into())
                                    .await?,
                                0
                            );
                            if reject {
                                return Err(AuthError::type_error("cookie-effect"));
                            }
                            Ok(())
                        })
                    }
                })),
            };
            let result = store
                .accept_invitation_with_session_effects_values(
                    &invitation.id.field_value(),
                    &"user-b".into(),
                    Some(&session.token.field_value()),
                    true,
                    Some(1).into(),
                    effects,
                )
                .await;
            if reject {
                assert!(
                    matches!(result, Err(AuthError::TypeError(message)) if message == "cookie-effect")
                );
            } else {
                let (_, _, cookie) = result?;
                assert_eq!(
                    required(cookie)?.active_team_id.field_value(),
                    team.id.field_value()
                );
            }
            assert_eq!(
                *events
                    .lock()
                    .map_err(|_| AuthError::internal("Event lock poisoned"))?,
                if reject {
                    vec!["secondary:team", "effect"]
                } else {
                    vec!["secondary:team", "effect", "secondary:organization"]
                }
            );
            let _ = initial.insert("activeTeamId".into(), team.id.field_value());
            if !reject {
                let _ = initial.insert("activeOrganizationId".into(), "org-a".into());
            }
            assert_eq!(
                *cached
                    .lock()
                    .map_err(|_| AuthError::internal("Cache fixture lock poisoned"))?,
                initial
            );
            let mut expected = write_database.then_some(original);
            if !reject && let Some(expected) = &mut expected {
                expected.active_team_id = Some(team.id.typed()?.clone());
                expected.active_organization_id = Some("org-a".into());
            }
            let db = store.connection();
            assert_eq!(
                session::Entity::find_by_id(session.id.typed()?.clone())
                    .one(db)
                    .await
                    .map_err(map_db_err)?,
                expected
            );
            assert_eq!(
                member::Entity::find()
                    .all(db)
                    .await
                    .map_err(map_db_err)?
                    .len(),
                usize::from(!reject)
            );
            assert_eq!(
                team_member::Entity::find()
                    .all(db)
                    .await
                    .map_err(map_db_err)?
                    .len(),
                usize::from(!reject)
            );
            assert_eq!(
                required(
                    team::Entity::find_by_id(team.id.typed()?.clone())
                        .one(db)
                        .await
                        .map_err(map_db_err)?
                )?
                .member_count,
                i64::from(!reject)
            );
            assert_eq!(
                required(
                    invitation::Entity::find_by_id(invitation.id.typed()?.clone())
                        .one(db)
                        .await
                        .map_err(map_db_err)?
                )?
                .status,
                if reject { "pending" } else { "accepted" }
            );
        }
    }
    Ok(())
}
