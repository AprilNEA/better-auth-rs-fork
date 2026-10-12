use super::*;
use better_auth::plugins::organization::RolePermissions;
use better_auth::plugins::organization::{
    hooks::{OrganizationActor, OrganizationEndpoint, OrganizationMemberEvent, OrganizationUser},
    types::OrganizationResponse,
};
use better_auth_core::{
    ApiErrorClass, CreateInvitation, CreateOrganization, CreateOrganizationRole, Member,
    UpdateOrganization,
};

#[path = "organization_error_cases.rs"]
mod cases;
use cases::Case;

struct ErrorHooks<S: AuthSchema> {
    events: Events,
    store: Arc<dyn AuthStore<S>>,
    case: Case,
}

impl<S: AuthSchema> ErrorHooks<S> {
    fn record(&self, name: &str) -> AuthResult<()> {
        trace_lock(&self.events)?.push(vec![FieldValue::from(name)].into());
        Ok(())
    }
}

#[async_trait]
impl<S: AuthSchema> OrganizationHooks for ErrorHooks<S> {
    async fn before_update_team(
        &self,
        updates: &mut UpdateTeam,
        data: OrganizationTeamEvent<'_>,
    ) -> AuthResult<()> {
        Hooks(self.events.clone())
            .before_update_team(updates, data)
            .await
    }
    async fn after_update_team(&self, data: OrganizationTeamEvent<'_>) -> AuthResult<()> {
        Hooks(self.events.clone()).after_update_team(data).await
    }
    async fn before_update_member_role(
        &self,
        role: &mut String,
        data: OrganizationMemberEvent<'_>,
    ) -> AuthResult<()> {
        self.record("beforeUpdateMemberRole")?;
        if self.case.removes_target() {
            self.store
                .delete_member_value(&data.member.id.field_value())
                .await?;
        }
        if self.case == Case::MemberUpdateHookMissing {
            *role = "member".into();
        }
        Ok(())
    }
    async fn after_update_member_role(
        &self,
        _: &str,
        _: OrganizationMemberEvent<'_>,
    ) -> AuthResult<()> {
        self.record("afterUpdateMemberRole")
    }
    async fn before_create_organization(
        &self,
        _: &mut CreateOrganization,
        _: &FieldValue,
    ) -> AuthResult<()> {
        self.record("beforeCreateOrganization")
    }
    async fn after_create_organization(&self, _: OrganizationMemberEvent<'_>) -> AuthResult<()> {
        self.record("afterCreateOrganization")
    }
    async fn before_update_organization(
        &self,
        _: &mut UpdateOrganization,
        _: OrganizationActor<'_>,
    ) -> AuthResult<()> {
        self.record("beforeUpdateOrganization")
    }
    async fn after_update_organization(
        &self,
        _: &OrganizationResponse,
        _: OrganizationActor<'_>,
    ) -> AuthResult<()> {
        self.record("afterUpdateOrganization")
    }
    async fn before_delete_organization(
        &self,
        _: OrganizationUser<'_>,
        _: OrganizationEndpoint<'_>,
    ) -> AuthResult<()> {
        self.record("beforeDeleteOrganization")
    }
    async fn after_delete_organization(
        &self,
        _: OrganizationUser<'_>,
        _: OrganizationEndpoint<'_>,
    ) -> AuthResult<()> {
        self.record("afterDeleteOrganization")
    }
}

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
    if case.member_target() {
        let _ = raw
            .insert_member(Member {
                field_order: Default::default(),
                additional_fields: Default::default(),
                id: "target-member".into(),
                organization_id: "organization".into(),
                user_id: "user-b".into(),
                role: "member".into(),
                created_at: date().into(),
            })
            .await?;
    }
    if matches!(
        case,
        Case::CancelInvitationMember | Case::CancelInvitationDenied
    ) {
        let mut invitation = CreateInvitation::new(
            "organization",
            "user-b@fields.test",
            "member",
            "user-a",
            date(),
        );
        invitation.id = Some("invitation-a".into());
        invitation.created_at = Some(date());
        let _ = raw.create_invitation(invitation).await?;
    }
    if case == Case::CancelInvitationMember {
        raw.delete_member("owner-member").await?;
    }
    if case.role_permissions() {
        let _ = raw
            .update_member_role("owner-member", "role-manager")
            .await?;
    }
    if case == Case::RoleUpdateMissingPermissions {
        let _ = raw
            .create_organization_role(CreateOrganizationRole {
                additional_fields: Default::default(),
                organization_id: "organization".into(),
                role: "custom".into(),
                permission: FieldMap::new().into(),
            })
            .await?;
    }
    if matches!(
        case,
        Case::OrgUpdateDenied | Case::OrgDeleteDenied | Case::CancelInvitationDenied
    ) {
        let _ = raw.update_member_role("owner-member", "member").await?;
    }
    if case.clears_active() {
        let _ = raw
            .update_session_fields(
                &token,
                FieldMap::from([
                    ("activeOrganizationId".into(), "organization".into()),
                    ("updatedAt".into(), date().into()),
                ]),
            )
            .await?;
    }
    let mut before = storage.snapshot_with_roles(true).await?;
    let events = Events::default();
    let events_for_field = events.clone();
    let mut policies = vec![(
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
    if case.clears_active() {
        let events = events.clone();
        policies.push((
            EntityRole::Session,
            declaration([(
                "updatedAt",
                UserFieldConfig {
                    field_type: UserFieldType::Date,
                    on_update: Some(better_auth_core::user_fields::UserFieldFactory::new(
                        move || {
                            event(&events, "session.updatedAt", "onUpdate".into())?;
                            Ok(date().into())
                        },
                    )),
                    ..Default::default()
                },
            )]),
        ));
    }
    let reader = auth_config(
        raw.clone(),
        Ids::default(),
        policies,
        OrganizationConfig {
            hooks: Some(Arc::new(ErrorHooks {
                events: events.clone(),
                store: raw,
                case,
            })),
            ac: case.role_permissions().then(|| {
                std::collections::HashMap::from([
                    (
                        "ac".into(),
                        vec!["create".into(), "update".into(), "read".into()],
                    ),
                    (
                        "organization".into(),
                        vec!["delete".into(), "update".into()],
                    ),
                ])
            }),
            roles: case.role_permissions().then(|| {
                std::collections::HashMap::from([(
                    "role-manager".into(),
                    RolePermissions {
                        ac: vec!["create".into(), "update".into()],
                        ..Default::default()
                    },
                )])
            }),
            allow_user_to_create_organization: case != Case::OrgCreateDenied,
            organization_limit: (case == Case::OrgCreateLimit).then_some(0),
            disable_organization_deletion: matches!(
                case,
                Case::OrgDeleteDisabled | Case::OrgDeleteDisabledSession
            ),
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
    let query = case.query();
    let result = if native {
        reader
            .call_endpoint(
                method,
                path,
                EndpointInput {
                    headers: (!case.headerless()).then_some(headers),
                    body,
                    query,
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
                    query,
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
    let (status_name, status, expected) = case.expected();
    let actual = if native {
        let error = required(result.err(), "Native endpoint must reject the operation")?;
        assert!(error.is_api_error()?);
        assert!(
            error.is_api_error_instance(ApiErrorClass::BetterAuth),
            "{case:?}"
        );
        assert!(
            error.is_api_error_instance(ApiErrorClass::BetterCall),
            "{case:?}"
        );
        assert_eq!(
            error.status_value()?,
            FieldValue::from(status_name),
            "{case:?}"
        );
        assert_eq!(error.status_code()?, status, "{case:?}");
        ordered(&error.body_value()?, &expected)?;
        let response = error.to_auth_response();
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
    let expected_events: Vec<FieldValue> = if case.clears_active() {
        vec![
            vec![
                FieldValue::from("session.updatedAt"),
                FieldValue::from("onUpdate"),
            ]
            .into(),
        ]
    } else if case.removes_target() {
        vec![vec![FieldValue::from("beforeUpdateMemberRole")].into()]
    } else {
        Vec::new()
    };
    assert_eq!(*trace_lock(&events)?, expected_events, "{case:?}");
    if case.clears_active() {
        let session = before
            .get_mut("session")
            .and_then(|sessions| sessions.first_mut())
            .ok_or_else(|| AuthError::internal("Expected complete stored Session"))?;
        let field = if storage.memory() {
            "activeOrganizationId"
        } else {
            "active_organization_id"
        };
        assert_eq!(
            session.get(field),
            Some(&FieldValue::from("organization")),
            "{case:?}"
        );
        let _ = session.insert(field.into(), FieldValue::Null);
    }
    if case.removes_target() {
        let members = before
            .get_mut("member")
            .ok_or_else(|| AuthError::internal("Expected complete stored Members"))?;
        assert!(
            members
                .iter()
                .any(|row| row.get("id") == Some(&FieldValue::from("target-member")))
        );
        members.retain(|row| row.get("id") != Some(&FieldValue::from("target-member")));
    }
    assert_eq!(storage.snapshot_with_roles(true).await?, before, "{case:?}");
    Ok(())
}

#[tokio::test]
async fn organization_errors_preserve_constructor_provenance() -> AuthResult<()> {
    for &case in Case::ALL {
        for native in [true, false] {
            let (raw, storage) = memory_fixture();
            check(raw, storage, case, native).await?;
            let (raw, storage) = sqlite_fixture().await?;
            check(raw, storage, case, native).await?;
        }
    }
    Ok(())
}
