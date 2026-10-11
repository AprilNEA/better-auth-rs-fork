use super::*;
use better_auth_core::{
    CreateInvitation, CreateOrganizationRole, InvitationStatus, UpdateOrganizationRole,
};
use better_auth_seaorm::sea_orm::{ConnectionTrait, DbBackend, Statement};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Model {
    Organization,
    Invitation,
    Team,
    Role,
}

impl Model {
    fn role(self) -> EntityRole {
        match self {
            Self::Organization => EntityRole::Organization,
            Self::Invitation => EntityRole::Invitation,
            Self::Team => EntityRole::Team,
            Self::Role => EntityRole::OrganizationRole,
        }
    }

    fn table(self) -> &'static str {
        match self {
            Self::Organization => "organization",
            Self::Invitation => "invitation",
            Self::Team => "team",
            Self::Role => "organizationRole",
        }
    }
}

fn expected(model: Model, updated: bool) -> FieldMap {
    let timestamp: FieldValue = if updated {
        "opaque-date:update-source"
    } else {
        "opaque-date:create-source"
    }
    .into();
    let name: FieldValue = if updated { "Updated" } else { "Created" }.into();
    let mut fields = match model {
        Model::Organization => FieldMap::from_iter([
            ("name".into(), name),
            ("slug".into(), "opaque-organization".into()),
            ("logo".into(), FieldValue::Null),
            ("createdAt".into(), timestamp),
            ("metadata".into(), "{}".into()),
        ]),
        Model::Invitation => FieldMap::from_iter([
            ("organizationId".into(), "organization".into()),
            ("email".into(), "opaque@fields.test".into()),
            ("role".into(), "member".into()),
            ("teamId".into(), FieldValue::Null),
            (
                "status".into(),
                if updated { "accepted" } else { "pending" }.into(),
            ),
            ("expiresAt".into(), date().into()),
            ("createdAt".into(), timestamp),
            ("inviterId".into(), "user-a".into()),
        ]),
        Model::Team => FieldMap::from_iter([
            ("name".into(), name),
            ("memberCount".into(), 0.into()),
            ("organizationId".into(), "organization".into()),
            ("createdAt".into(), timestamp),
            ("updatedAt".into(), date().into()),
        ]),
        Model::Role => FieldMap::from_iter([
            ("organizationId".into(), "organization".into()),
            (
                "role".into(),
                if updated { "renamed" } else { "custom" }.into(),
            ),
            ("permission".into(), "{}".into()),
            ("createdAt".into(), timestamp),
            ("updatedAt".into(), date().into()),
        ]),
    };
    let _ = fields.insert("id".into(), "opaque-row".into());
    fields
}

fn stored(storage: &Storage, expected: &FieldMap) -> FieldMap {
    expected
        .iter()
        .map(|(name, value)| {
            let physical = if storage.memory() {
                name.as_str()
            } else {
                match name.as_str() {
                    "organizationId" => "organization_id",
                    "createdAt" => "created_at",
                    "updatedAt" => "updated_at",
                    "teamId" => "team_id",
                    "expiresAt" => "expires_at",
                    "inviterId" => "inviter_id",
                    "memberCount" => "member_count",
                    name => name,
                }
            };
            (
                physical.to_owned(),
                if !storage.memory() && value.as_date().is_some() {
                    stored_date(storage)
                } else {
                    value.clone()
                },
            )
        })
        .collect()
}

fn check_output<T: AuthRecordFields + serde::Serialize>(
    actual: T,
    expected: &FieldMap,
) -> AuthResult<()> {
    let expected = FieldValue::from(expected.clone());
    ordered(&actual.field_values()?.into(), &expected)?;
    assert_eq!(
        serde_json::to_vec(&actual)?,
        serde_json::to_vec(&expected.json()?)?
    );
    Ok(())
}

async fn create<S: AuthSchema>(store: &dyn AuthStore<S>, model: Model) -> AuthResult<()> {
    let fields = FieldMap::from_iter([("createdAt".into(), "create-source".into())]);
    let output = expected(model, false);
    match model {
        Model::Organization => {
            let mut input = CreateOrganization::new("Created", "opaque-organization")
                .with_metadata(FieldMap::new().into());
            input.logo = None.into();
            check_output(store.create_organization(input).await?, &output)
        }
        Model::Invitation => {
            let mut input = CreateInvitation::new(
                "organization",
                "opaque@fields.test",
                "member",
                "user-a",
                date(),
            );
            input.additional_fields = fields;
            check_output(store.create_invitation(input).await?, &output)
        }
        Model::Team => check_output(
            store
                .create_team(CreateTeam {
                    name: "Created".into(),
                    organization_id: "organization".into(),
                    updated_at: Some(date()),
                    additional_fields: fields,
                    ..Default::default()
                })
                .await?,
            &output,
        ),
        Model::Role => {
            let mut fields = fields;
            let _ = fields.insert("updatedAt".into(), date().into());
            check_output(
                store
                    .create_organization_role(CreateOrganizationRole {
                        organization_id: "organization".into(),
                        role: "custom".into(),
                        permission: FieldMap::new().into(),
                        additional_fields: fields,
                    })
                    .await?,
                &output,
            )
        }
    }
}

async fn update<S: AuthSchema>(store: &dyn AuthStore<S>, model: Model) -> AuthResult<()> {
    let output = expected(model, true);
    match model {
        Model::Organization => check_output(
            store
                .update_organization(
                    "opaque-row",
                    UpdateOrganization {
                        name: Some("Updated".into()),
                        ..Default::default()
                    },
                )
                .await?,
            &output,
        ),
        Model::Invitation => check_output(
            required(
                store
                    .update_invitation_status("opaque-row", InvitationStatus::Accepted)
                    .await?,
                "Expected updated Invitation",
            )?,
            &output,
        ),
        Model::Team => check_output(
            store
                .update_team(
                    "opaque-row",
                    UpdateTeam {
                        name: Some("Updated".into()),
                        ..Default::default()
                    },
                )
                .await?,
            &output,
        ),
        Model::Role => check_output(
            store
                .update_organization_role(
                    "opaque-row",
                    UpdateOrganizationRole {
                        role: Some("renamed".into()),
                        ..Default::default()
                    },
                )
                .await?,
            &output,
        ),
    }
}

async fn check_storage(
    storage: &Storage,
    model: Model,
    expected: &mut Snapshot,
    started: i64,
    finished: i64,
) -> AuthResult<Option<chrono::DateTime<chrono::Utc>>> {
    let actual = storage.snapshot_with_roles(true).await?;
    let internal = if let (Model::Organization, Storage::Sqlite(database)) = (model, storage) {
        let row = database
            .query_one_raw(Statement::from_string(
                DbBackend::Sqlite,
                "SELECT updated_at FROM organization WHERE id = 'opaque-row'".to_owned(),
            ))
            .await
            .map_err(|error| AuthError::internal(error.to_string()))?
            .ok_or_else(|| AuthError::internal("Expected private Organization timestamp"))?;
        let timestamp = row
            .try_get::<chrono::DateTime<chrono::Utc>>("", "updated_at")
            .map_err(|error| AuthError::internal(error.to_string()))?;
        assert!((started..=finished).contains(&timestamp.timestamp_millis()));
        let observed = actual
            .get("organization")
            .and_then(|rows| {
                rows.iter()
                    .find(|row| row.get("id").and_then(FieldValue::as_str) == Some("opaque-row"))
            })
            .and_then(|row| row.get("updated_at"))
            .ok_or_else(|| AuthError::internal("Expected raw private Organization timestamp"))?;
        let expected = expected
            .get_mut("organization")
            .and_then(|rows| {
                rows.iter_mut()
                    .find(|row| row.get("id").and_then(FieldValue::as_str) == Some("opaque-row"))
            })
            .ok_or_else(|| AuthError::internal("Expected Organization storage row"))?;
        let _ = expected.insert("updated_at".into(), observed.clone());
        Some(timestamp)
    } else {
        None
    };
    assert_eq!(actual, *expected, "{model:?}");
    Ok(internal)
}

async fn check<S: AuthSchema>(
    raw: Arc<dyn AuthStore<S>>,
    storage: Storage,
    model: Model,
) -> AuthResult<()> {
    let _ = seed(raw.clone(), false, "user-a").await?;
    let mut after = storage.snapshot_with_roles(true).await?;
    let events = Events::default();
    let mut policies = declaration([(
        "createdAt",
        UserFieldConfig {
            on_update: Some(Arc::new({
                let events = events.clone();
                move || {
                    event(&events, "createdAt", "onUpdate", FieldValue::Undefined)?;
                    Ok("update-source".into())
                }
            })),
            transform: Some(FieldTransforms {
                input: Some(UserFieldTransform::new({
                    let events = events.clone();
                    move |value| {
                        let source = if model == Model::Organization && value.as_date().is_some() {
                            event(&events, "createdAt", "input", "native-date".into())?;
                            "create-source"
                        } else {
                            event(&events, "createdAt", "input", value.clone())?;
                            required(value.as_str(), "Expected replaced timestamp input")?
                        };
                        Ok(format!("opaque-date:{source}").into())
                    }
                })),
                output: Some(UserFieldTransform::new({
                    let events = events.clone();
                    move |value| {
                        event(&events, "createdAt", "output", value.clone())?;
                        Ok(value)
                    }
                })),
            }),
            ..Default::default()
        },
    )]);
    if matches!(model, Model::Team | Model::Role) {
        let _ = policies.fields_mut().insert(
            "updatedAt".into(),
            UserFieldConfig {
                field_type: UserFieldType::Date,
                on_update: Some(Arc::new(|| Ok(date().into()))),
                ..Default::default()
            },
        );
    }
    let mut settings = config();
    settings.advanced.database.generate_id = Some(IdGeneration::Custom(IdGenerator::new(|_| {
        Ok(Some("opaque-row".into()))
    })));
    let mut plugin = OrganizationConfig {
        dynamic_access_control: true,
        ..Default::default()
    };
    plugin.teams.enabled = true;
    let auth = BetterAuth::new(settings)
        .store_arc(raw)
        .plugin(OrganizationPlugin::with_config(plugin))
        .plugin(Fields(vec![(
            model.role(),
            declaration([(
                "createdAt",
                UserFieldConfig {
                    field_type: UserFieldType::Date,
                    field_name: Some("id".into()),
                    returned: Some(false),
                    ..Default::default()
                },
            )]),
        )]))
        .plugin(Fields(vec![(model.role(), policies)]))
        .build()
        .await?;
    let started = chrono::Utc::now().timestamp_millis();
    create(auth.store().as_ref(), model).await?;
    let finished = chrono::Utc::now().timestamp_millis();
    let rows = after
        .get_mut(model.table())
        .ok_or_else(|| AuthError::internal("Expected Organization model table"))?;
    rows.push(stored(&storage, &expected(model, false)));
    rows.sort_by(|left, right| {
        left.get("id")
            .and_then(FieldValue::as_str)
            .cmp(&right.get("id").and_then(FieldValue::as_str))
    });
    let created = check_storage(&storage, model, &mut after, started, finished).await?;
    let started = chrono::Utc::now().timestamp_millis();
    update(auth.store().as_ref(), model).await?;
    let finished = chrono::Utc::now().timestamp_millis();
    let row = after
        .get_mut(model.table())
        .and_then(|rows| {
            rows.iter_mut()
                .find(|row| row.get("id").and_then(FieldValue::as_str) == Some("opaque-row"))
        })
        .ok_or_else(|| AuthError::internal("Expected created Organization model row"))?;
    *row = stored(&storage, &expected(model, true));
    let updated = check_storage(&storage, model, &mut after, started, finished).await?;
    if let (Some(created), Some(updated)) = (created, updated) {
        assert!(updated >= created);
    }
    let expected_events: Vec<FieldValue> = [
        vec![
            "createdAt".into(),
            "input".into(),
            if model == Model::Organization {
                "native-date"
            } else {
                "create-source"
            }
            .into(),
        ],
        vec![
            "createdAt".into(),
            "output".into(),
            "opaque-date:create-source".into(),
        ],
        vec!["createdAt".into(), "onUpdate".into(), FieldValue::Undefined],
        vec!["createdAt".into(), "input".into(), "update-source".into()],
        vec![
            "createdAt".into(),
            "output".into(),
            "opaque-date:update-source".into(),
        ],
    ]
    .into_iter()
    .map(FieldValue::from)
    .collect();
    ordered(
        &trace_lock(&events)?.clone().into(),
        &expected_events.into(),
    )?;
    Ok(())
}

#[tokio::test]
async fn memory_organization_models_write_replaced_timestamp_before_output() -> AuthResult<()> {
    for model in [
        Model::Organization,
        Model::Invitation,
        Model::Team,
        Model::Role,
    ] {
        let (raw, storage) = memory_fixture();
        check(raw, storage, model).await?;
    }
    Ok(())
}

#[tokio::test]
async fn sqlite_organization_models_read_raw_timestamp_before_output() -> AuthResult<()> {
    for model in [
        Model::Organization,
        Model::Invitation,
        Model::Team,
        Model::Role,
    ] {
        let (raw, storage) = sqlite_fixture().await?;
        check(raw, storage, model).await?;
    }
    Ok(())
}
