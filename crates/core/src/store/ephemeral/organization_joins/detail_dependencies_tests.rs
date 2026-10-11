//! Paired with organization-detail-dependencies.test.ts against Better Auth 1.7.6.
#![expect(
    clippy::panic_in_result_fn,
    reason = "The paired contract propagates setup errors and asserts complete values, callback order, and storage."
)]

use super::*;
use crate::FieldDate;
use crate::organization_fields::OrganizationFields;
use crate::user_fields::{
    FieldTransforms, UserFieldConfig, UserFieldReference, UserFieldTransform,
};

fn date() -> Value {
    FieldDate::from_milliseconds(1_893_456_000_000.0).into()
}

fn page(rows: Vec<FieldMap>) -> Value {
    rows.into_iter().map(Value::from).collect::<Vec<_>>().into()
}

fn result_fields(result: OrganizationDetails) -> AuthResult<FieldMap> {
    let mut fields = result.organization.field_values()?;
    let _ = fields.insert(
        "invitations".into(),
        page(
            result
                .invitations
                .iter()
                .map(AuthRecordFields::field_values)
                .collect::<AuthResult<_>>()?,
        ),
    );
    let _ = fields.insert(
        "members".into(),
        page(
            result
                .members
                .iter()
                .map(|member| {
                    let mut fields = member.member.field_values()?;
                    let _ = fields.insert("user".into(), member.user.field_values()?.into());
                    Ok(fields)
                })
                .collect::<AuthResult<_>>()?,
        ),
    );
    let _ = fields.insert(
        "teams".into(),
        page(
            result
                .teams
                .ok_or_else(|| AuthError::internal("Expected team page"))?
                .iter()
                .map(AuthRecordFields::field_values)
                .collect::<AuthResult<_>>()?,
        ),
    );
    Ok(fields)
}

async fn check(native: bool, mapped: bool, reject: bool) -> AuthResult<()> {
    let events = Arc::new(Mutex::new(Vec::<(&'static str, Value)>::new()));
    let trace = |name: &'static str| {
        let events = events.clone();
        UserFieldConfig {
            transform: Some(FieldTransforms {
                output: Some(UserFieldTransform::new(move |value| {
                    events
                        .lock()
                        .map_err(|error| AuthError::internal(error.to_string()))?
                        .push((
                            name,
                            crate::StructuredCloneContext::new().clone_value(&value)?,
                        ));
                    if reject && name == "invitation.role" {
                        return Err(AuthError::type_error("detail-dependency-output-rejected"));
                    }
                    Ok(value)
                })),
                ..Default::default()
            }),
            ..Default::default()
        }
    };
    let mut config = AuthConfig::default();
    config.advanced.database.joins = Some(native);
    let _ = config
        .user
        .fields_mut()
        .insert("name".into(), trace("user.name"));
    let store = EphemeralStore::new(Arc::new(config));
    let mut fields = OrganizationFields::default();
    for (name, physical) in [
        ("invitation", "stored_invitation"),
        ("member", "stored_member"),
    ] {
        let _ = fields.organization.fields_mut().insert(
            name.into(),
            UserFieldConfig {
                field_name: mapped.then(|| physical.to_owned()),
                ..trace(if name == "invitation" {
                    "organization.invitation"
                } else {
                    "organization.member"
                })
            },
        );
    }
    let _ = fields
        .invitation
        .fields_mut()
        .insert("role".into(), trace("invitation.role"));
    let _ = fields
        .member
        .fields_mut()
        .insert("role".into(), trace("member.role"));
    let _ = fields
        .team
        .fields_mut()
        .insert("name".into(), trace("team.name"));
    for (schema, reference) in [
        (&mut fields.member, "invitation"),
        (&mut fields.team, "member"),
    ] {
        let _ = schema.fields_mut().insert(
            "organizationId".into(),
            UserFieldConfig {
                references: Some(UserFieldReference {
                    model: "organization".into(),
                    field: reference.into(),
                    ..Default::default()
                }),
                ..Default::default()
            },
        );
    }
    store.configure_organization_fields(fields)?;
    let parent: FieldMap = [
        ("id".into(), "organization".into()),
        ("name".into(), "Organization".into()),
        ("slug".into(), "organization".into()),
        ("logo".into(), Value::Null),
        ("metadata".into(), Value::Null),
        ("createdAt".into(), date()),
    ]
    .into();
    let invitation: FieldMap = [
        ("id".into(), "invitation".into()),
        ("organizationId".into(), "organization".into()),
        ("email".into(), "owner@detail-dependencies.test".into()),
        ("role".into(), "member".into()),
        ("teamId".into(), Value::Null),
        ("status".into(), "pending".into()),
        ("inviterId".into(), "owner".into()),
        ("createdAt".into(), date()),
        ("expiresAt".into(), date()),
    ]
    .into();
    let member: FieldMap = [
        ("id".into(), "member".into()),
        ("organizationId".into(), "stale-member-key".into()),
        ("userId".into(), "owner".into()),
        ("role".into(), "member".into()),
        ("createdAt".into(), date()),
    ]
    .into();
    let team: FieldMap = [
        ("id".into(), "team".into()),
        ("organizationId".into(), "stale-team-key".into()),
        ("name".into(), "Team".into()),
        ("memberCount".into(), 0.into()),
        ("createdAt".into(), date()),
        ("updatedAt".into(), Value::Null),
    ]
    .into();
    let user: FieldMap = [
        ("id".into(), "owner".into()),
        ("name".into(), "Owner".into()),
        ("email".into(), "owner@detail-dependencies.test".into()),
        ("emailVerified".into(), true.into()),
        ("image".into(), Value::Null),
        ("createdAt".into(), date()),
        ("updatedAt".into(), date()),
    ]
    .into();
    let mut stored_parent = parent.clone();
    let _ = stored_parent.insert(
        if mapped {
            "stored_invitation"
        } else {
            "invitation"
        }
        .into(),
        "stale-member-key".into(),
    );
    let _ = stored_parent.insert(
        if mapped { "stored_member" } else { "member" }.into(),
        "stale-team-key".into(),
    );
    {
        let mut state = store.lock()?;
        state.organizations.push(stored_parent);
        state.invitations.push(invitation.clone());
        state.members.push(member.clone());
        state.teams.push(team.clone());
        state.users.push(UserView::from_field_values(user.clone())?);
    }
    let roles = [
        EntityRole::Organization,
        EntityRole::Invitation,
        EntityRole::Member,
        EntityRole::Team,
        EntityRole::User,
    ];
    let before = roles
        .iter()
        .map(|role| store.storage_rows(*role))
        .collect::<AuthResult<Vec<_>>>()?;
    let result = store
        .get_organization_details(OrganizationDetailsQuery {
            organization: OrganizationKey::Id("organization"),
            members_limit: None,
            users_limit: 100.0,
            include_teams: true,
        })
        .await;
    if reject {
        assert!(
            matches!(result, Err(AuthError::TypeError(message)) if message == "detail-dependency-output-rejected")
        );
    } else {
        let mut expected = parent;
        let _ = expected.insert("invitations".into(), page(vec![invitation.clone()]));
        let mut visible_member = member.clone();
        let _ = visible_member.insert(
            "user".into(),
            FieldMap::from_iter(
                ["id", "name", "email", "image"].map(|name| (name.into(), user[name].clone())),
            )
            .into(),
        );
        let _ = expected.insert(
            "members".into(),
            page(if native {
                vec![visible_member]
            } else {
                Vec::new()
            }),
        );
        let _ = expected.insert(
            "teams".into(),
            page(if native { vec![team] } else { Vec::new() }),
        );
        assert_eq!(
            result_fields(
                result?.ok_or_else(|| AuthError::internal("Expected organization details"))?
            )?,
            expected
        );
    }
    let mut expected_events = vec![
        (
            "organization.invitation",
            if native && !mapped {
                page(vec![invitation])
            } else {
                "stale-member-key".into()
            },
        ),
        (
            "organization.member",
            if native && !mapped {
                page(vec![member])
            } else {
                "stale-team-key".into()
            },
        ),
        ("invitation.role", "member".into()),
    ];
    if !reject && native {
        expected_events.extend([
            ("member.role", "member".into()),
            ("team.name", "Team".into()),
            ("user.name", "Owner".into()),
        ]);
    }
    assert_eq!(
        *events
            .lock()
            .map_err(|error| AuthError::internal(error.to_string()))?,
        expected_events
    );
    assert_eq!(
        roles
            .iter()
            .map(|role| store.storage_rows(*role))
            .collect::<AuthResult<Vec<_>>>()?,
        before
    );
    Ok(())
}

#[tokio::test]
async fn full_details_replace_each_relation_before_later_fallback_queries() -> AuthResult<()> {
    for native in [false, true] {
        for mapped in [false, true] {
            for reject in [false, true] {
                check(native, mapped, reject).await?;
            }
        }
    }
    Ok(())
}
