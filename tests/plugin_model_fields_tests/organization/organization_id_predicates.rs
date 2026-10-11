use super::member_contract_support::{date, memory_fixture, ordered};
use super::*;
use better_auth_core::{AuthRecordFields, CreateInvitation, InvitationStatus, SchemaValue};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Model {
    Organization,
    Invitation,
    Team,
}

impl Model {
    fn role(self) -> EntityRole {
        match self {
            Self::Organization => EntityRole::Organization,
            Self::Invitation => EntityRole::Invitation,
            Self::Team => EntityRole::Team,
        }
    }

    fn table(self) -> &'static str {
        match self {
            Self::Organization => "organization",
            Self::Invitation => "invitation",
            Self::Team => "team",
        }
    }

    fn observed_field(self) -> &'static str {
        if self == Self::Invitation {
            "status"
        } else {
            "name"
        }
    }
}

#[derive(Clone, Copy, Debug)]
enum Selector {
    SharedObject,
    DistinctObject,
    Null,
    Undefined,
}

fn object_id() -> FieldValue {
    FieldMap::from_iter([("key".into(), "same".into())]).into()
}

fn fields(model: Model, label: &str, updated: bool, expiry: bool) -> FieldMap {
    let name: FieldValue = if updated { "changed" } else { label }.into();
    match model {
        Model::Organization => FieldMap::from_iter([
            ("name".into(), name),
            ("slug".into(), format!("id-{label}").into()),
            ("logo".into(), FieldValue::Null),
            ("createdAt".into(), date().into()),
            ("metadata".into(), "{}".into()),
        ]),
        Model::Invitation => FieldMap::from_iter([
            ("organizationId".into(), "organization".into()),
            ("email".into(), format!("{label}@id.fields.test").into()),
            ("role".into(), "member".into()),
            ("teamId".into(), FieldValue::Null),
            (
                "status".into(),
                if updated { "accepted" } else { "pending" }.into(),
            ),
            (
                "expiresAt".into(),
                if expiry { expiry_date() } else { date() }.into(),
            ),
            ("createdAt".into(), date().into()),
            ("inviterId".into(), "user-a".into()),
        ]),
        Model::Team => FieldMap::from_iter([
            ("name".into(), name),
            ("memberCount".into(), 0.into()),
            ("organizationId".into(), "organization".into()),
            ("createdAt".into(), date().into()),
            ("updatedAt".into(), date().into()),
        ]),
    }
}

fn expiry_date() -> FieldDate {
    FieldDate::from_milliseconds(date().milliseconds() + 1_000.0)
}

fn visible(model: Model, id: &FieldValue, updated: bool, expiry: bool) -> FieldValue {
    let mut fields = fields(model, "first", updated, expiry);
    let _ = fields.insert(
        "id".into(),
        if id.is_object() {
            "[object Object]".into()
        } else {
            FieldValue::Undefined
        },
    );
    fields.into()
}

async fn create(
    store: &dyn AuthStore<StatelessSchema>,
    model: Model,
    label: &str,
    id: FieldValue,
) -> AuthResult<()> {
    let extras = [("id".into(), id.clone())].into();
    match model {
        Model::Organization => {
            let _ = store
                .insert_organization(Organization {
                    field_order: Default::default(),
                    id: SchemaValue::from_field(id),
                    name: label.into(),
                    slug: format!("id-{label}").into(),
                    logo: None.into(),
                    metadata: Some(FieldValue::from("{}")).into(),
                    created_at: date().into(),
                    additional_fields: Default::default(),
                })
                .await?;
        }
        Model::Invitation => {
            let mut input = CreateInvitation::new(
                "organization",
                format!("{label}@id.fields.test"),
                "member",
                "user-a",
                date(),
            );
            input.created_at = Some(date());
            input.additional_fields = extras;
            let _ = store.create_invitation(input).await?;
        }
        Model::Team => {
            let _ = store
                .create_team(CreateTeam {
                    name: label.into(),
                    organization_id: "organization".into(),
                    created_at: Some(date()),
                    updated_at: Some(date()),
                    additional_fields: extras,
                    ..Default::default()
                })
                .await?;
        }
    }
    Ok(())
}

async fn read(
    store: &dyn AuthStore<StatelessSchema>,
    model: Model,
    id: &FieldValue,
) -> AuthResult<Option<FieldMap>> {
    match model {
        Model::Organization => store
            .get_organization_by_id_value(id)
            .await?
            .map(|row| row.field_values())
            .transpose(),
        Model::Invitation => store
            .get_invitation_by_id_value(id)
            .await?
            .map(|row| row.field_values())
            .transpose(),
        Model::Team => store
            .get_team_value(id)
            .await?
            .map(|row| row.field_values())
            .transpose(),
    }
}

async fn update(
    store: &dyn AuthStore<StatelessSchema>,
    model: Model,
    id: &FieldValue,
) -> AuthResult<Option<FieldMap>> {
    match model {
        Model::Organization => store
            .update_organization_value(
                id,
                UpdateOrganization {
                    name: Some("changed".into()),
                    ..Default::default()
                },
            )
            .await?
            .field_values()
            .map(Some),
        Model::Invitation => store
            .update_invitation_status_value(id, InvitationStatus::Accepted)
            .await?
            .map(|row| row.field_values())
            .transpose(),
        Model::Team => store
            .update_team_value(
                id,
                UpdateTeam {
                    name: Some("changed".into()),
                    updated_at: Some(Some(date())),
                    ..Default::default()
                },
            )
            .await?
            .field_values()
            .map(Some),
    }
}

async fn check(model: Model, selector: Selector) -> AuthResult<()> {
    let (raw, storage) = memory_fixture();
    let events = Arc::new(Mutex::new(Vec::<FieldValue>::new()));
    let output_events = events.clone();
    let mut options = OrganizationConfig::default();
    options.teams.enabled = true;
    let auth = BetterAuth::new(config())
        .store_arc(raw)
        .plugin(OrganizationPlugin::with_config(options))
        .plugin(Fields(vec![(
            model.role(),
            UserConfig {
                additional_fields: Some(
                    [(
                        model.observed_field().into(),
                        UserFieldConfig {
                            transform: Some(FieldTransforms {
                                output: Some(UserFieldTransform::new(move |value| {
                                    trace_lock(&output_events)?.push(value.clone());
                                    Ok(value)
                                })),
                                ..Default::default()
                            }),
                            ..Default::default()
                        },
                    )]
                    .into(),
                ),
            },
        )]))
        .build()
        .await?;
    let stored_id = match selector {
        Selector::SharedObject | Selector::DistinctObject => object_id(),
        Selector::Null | Selector::Undefined => false.into(),
    };
    let selected_id = match selector {
        Selector::SharedObject => stored_id.clone(),
        Selector::DistinctObject => object_id(),
        Selector::Null => FieldValue::Null,
        Selector::Undefined => FieldValue::Undefined,
    };
    for (label, id) in [
        ("first", stored_id.clone()),
        ("second", stored_id.clone()),
        ("other", "other".into()),
    ] {
        create(auth.store().as_ref(), model, label, id).await?;
    }
    trace_lock(&events)?.clear();
    let before = storage.snapshot().await?;
    let found = !matches!(selector, Selector::DistinctObject);
    let actual = read(auth.store().as_ref(), model, &selected_id).await?;
    if found {
        ordered(
            &required(actual, "Expected selected ID row")?.into(),
            &visible(model, &stored_id, false, false),
        )?;
    } else {
        assert!(actual.is_none());
    }
    assert_eq!(storage.snapshot().await?, before);
    let actual = update(auth.store().as_ref(), model, &selected_id).await;
    if found {
        ordered(
            &required(actual?, "Expected updated ID row")?.into(),
            &visible(model, &stored_id, true, false),
        )?;
    } else if model == Model::Invitation {
        assert!(actual?.is_none());
    } else {
        let message = if model == Model::Organization {
            "Organization not found"
        } else {
            "Team not found"
        };
        assert!(matches!(actual, Err(AuthError::NotFound(error)) if error == message));
    }
    let mut after = before;
    if found {
        for row in required(after.get_mut(model.table()), "Expected model storage")? {
            if row.get("id").and_then(FieldValue::as_str) != Some("other") {
                let _ = row.insert(
                    model.observed_field().into(),
                    if model == Model::Invitation {
                        "accepted"
                    } else {
                        "changed"
                    }
                    .into(),
                );
            }
        }
    }
    assert_eq!(storage.snapshot().await?, after);
    let mut expected_events = if found {
        vec![
            if model == Model::Invitation {
                "pending"
            } else {
                "first"
            }
            .into(),
            if model == Model::Invitation {
                "accepted"
            } else {
                "changed"
            }
            .into(),
        ]
    } else {
        Vec::<FieldValue>::new()
    };
    if model == Model::Invitation {
        let expires_at = required(expiry_date().to_datetime()?, "Expected valid expiry")?;
        let actual = auth
            .store()
            .update_invitation_expiry_value(&selected_id, expires_at)
            .await;
        if found {
            ordered(
                &actual?.field_values()?.into(),
                &visible(model, &stored_id, true, true),
            )?;
            for row in required(after.get_mut(model.table()), "Expected Invitation storage")? {
                if row.get("id").and_then(FieldValue::as_str) != Some("other") {
                    let _ = row.insert("expiresAt".into(), expiry_date().into());
                }
            }
            expected_events.push("accepted".into());
        } else {
            assert!(
                matches!(actual, Err(AuthError::NotFound(error)) if error == "Invitation not found")
            );
        }
        assert_eq!(storage.snapshot().await?, after);
    }
    assert_eq!(*trace_lock(&events)?, expected_events);
    Ok(())
}

#[tokio::test]
async fn memory_organization_id_predicates_preserve_identity_and_nullish_queries() -> AuthResult<()>
{
    for model in [Model::Organization, Model::Invitation, Model::Team] {
        for selector in [
            Selector::SharedObject,
            Selector::DistinctObject,
            Selector::Null,
            Selector::Undefined,
        ] {
            check(model, selector).await?;
        }
    }
    Ok(())
}
