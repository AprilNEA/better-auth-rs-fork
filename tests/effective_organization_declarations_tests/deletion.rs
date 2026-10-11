use super::*;
use better_auth_core::{
    CreateInvitation, CreateOrganizationRole, Member, Organization,
    store::{InvitationStore, MemberStore, OrganizationRoleStore, OrganizationStore, TeamStore},
};
use std::collections::BTreeMap;

type Snapshot = BTreeMap<&'static str, Vec<FieldMap>>;

fn snapshot(store: &EphemeralStore) -> AuthResult<Snapshot> {
    [
        ("user", EntityRole::User),
        ("session", EntityRole::Session),
        ("account", EntityRole::Account),
        ("verification", EntityRole::Verification),
        ("organization", EntityRole::Organization),
        ("member", EntityRole::Member),
        ("invitation", EntityRole::Invitation),
        ("team", EntityRole::Team),
        ("teamMember", EntityRole::TeamMember),
        ("organizationRole", EntityRole::OrganizationRole),
    ]
    .into_iter()
    .map(|(name, role)| Ok((name, store.storage_rows(role)?)))
    .collect()
}

async fn seed(store: &EphemeralStore) -> AuthResult<()> {
    let date = FieldDate::from_milliseconds(1_893_456_000_000.0);
    for id in ["deleted", "retained"] {
        let _ = store
            .insert_organization(Organization {
                id: id.into(),
                name: id.into(),
                slug: id.into(),
                created_at: date.clone().into(),
                ..Default::default()
            })
            .await?;
        let _ = store
            .insert_member(Member {
                field_order: Default::default(),
                additional_fields: Default::default(),
                id: format!("{id}-member").into(),
                organization_id: id.into(),
                user_id: "owner".into(),
                role: "member".into(),
                created_at: date.clone().into(),
            })
            .await?;
        let mut invitation =
            CreateInvitation::new(id, "owner@delete.test", "member", "owner", date.clone());
        invitation.id = Some(format!("{id}-invitation"));
        invitation.created_at = Some(date.clone());
        let _ = store.create_invitation(invitation).await?;
        let team = store
            .create_team(CreateTeam {
                id: Some(format!("{id}-team")),
                organization_id: id.into(),
                name: id.into(),
                created_at: Some(date.clone()),
                ..Default::default()
            })
            .await?;
        let _ = store
            .add_team_member(&team.id, "owner", None)
            .await?
            .ok_or_else(|| AuthError::internal("Expected the seeded Team membership"))?;
        let _ = store
            .create_organization_role(CreateOrganizationRole {
                organization_id: id.into(),
                role: "reader".into(),
                permission: FieldMap::new().into(),
                additional_fields: [
                    ("id".into(), format!("{id}-role").into()),
                    ("createdAt".into(), date.clone().into()),
                ]
                .into(),
            })
            .await?;
    }
    Ok(())
}

struct MissingInvitationReference;

#[async_trait]
impl<S: AuthSchema> AuthPlugin<S> for MissingInvitationReference {
    fn name(&self) -> &'static str {
        "explicit-delete-models"
    }
    fn routes(&self) -> Vec<AuthRoute> {
        Vec::new()
    }
    async fn on_init(&self, context: &mut AuthInitContext<S>) -> AuthResult<()> {
        for role in [EntityRole::Organization, EntityRole::Invitation] {
            context.register_model_fields(
                role,
                UserConfig {
                    additional_fields: Some(Default::default()),
                },
            )?;
        }
        context.register_model_fields(
            EntityRole::Member,
            UserConfig {
                additional_fields: Some(
                    [("organizationId".into(), UserFieldConfig::default())].into(),
                ),
            },
        )
    }
    async fn on_request(
        &self,
        _: &AuthRequest,
        _: &AuthContext<S>,
    ) -> AuthResult<Option<AuthResponse>> {
        Ok(None)
    }
}

async fn fixture(
    missing_reference: bool,
) -> AuthResult<(EphemeralStore, BetterAuth<StatelessSchema>)> {
    let config = config();
    let raw = EphemeralStore::new(Arc::new(config.clone()));
    seed(&raw).await?;
    let builder = BetterAuth::new(config).store(raw.clone());
    let auth = if missing_reference {
        builder.plugin(MissingInvitationReference).build().await?
    } else {
        builder
            .plugin(OrganizationPlugin::with_config(
                OrganizationConfig::default(),
            ))
            .build()
            .await?
    };
    Ok((raw, auth))
}

fn remove_target(mut stored: Snapshot, tables: &[&'static str]) -> AuthResult<Snapshot> {
    for table in tables {
        let rows = stored
            .get_mut(table)
            .ok_or_else(|| AuthError::internal("Expected the observed table"))?;
        let _ = rows.remove(0);
    }
    Ok(stored)
}

#[tokio::test]
async fn organization_delete_preserves_disabled_team_and_role_storage() -> AuthResult<()> {
    let (raw, auth) = fixture(false).await?;
    let before = snapshot(&raw)?;
    for table in [
        "organization",
        "member",
        "invitation",
        "team",
        "teamMember",
        "organizationRole",
    ] {
        assert_eq!(before.get(table).map(Vec::len), Some(2), "{table}");
    }
    auth.store().delete_organization("deleted").await?;
    assert_eq!(
        snapshot(&raw)?,
        remove_target(before, &["organization", "member", "invitation"])?
    );
    Ok(())
}

#[tokio::test]
async fn organization_delete_rolls_back_but_raw_cleanup_preserves_preceding_deletes()
-> AuthResult<()> {
    for transactional in [false, true] {
        let (raw, auth) = fixture(true).await?;
        let before = snapshot(&raw)?;
        let result = if transactional {
            auth.store().delete_organization("deleted").await
        } else {
            auth.store().delete_organization_records("deleted").await
        };
        let error = result
            .err()
            .ok_or_else(|| AuthError::internal("Expected the missing Invitation reference"))?;
        assert!(
            matches!(&error, AuthError::Config(message) if message == "Field organizationId not found in model invitation"),
            "{error}"
        );
        let expected = if transactional {
            before
        } else {
            remove_target(before, &["member"])?
        };
        assert_eq!(snapshot(&raw)?, expected, "transactional={transactional}");
    }
    Ok(())
}
