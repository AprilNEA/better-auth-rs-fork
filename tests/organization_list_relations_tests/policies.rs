use super::*;

struct Fields(Vec<(EntityRole, UserConfig)>);
#[async_trait]
impl<S: AuthSchema> AuthPlugin<S> for Fields {
    fn name(&self) -> &'static str {
        "organization-list-relation-fields"
    }
    fn routes(&self) -> Vec<AuthRoute> {
        Vec::new()
    }
    async fn on_init(&self, context: &mut AuthInitContext<S>) -> AuthResult<()> {
        for (role, fields) in &self.0 {
            context.register_model_fields(*role, fields.clone())?;
        }
        Ok(())
    }
    async fn on_request(
        &self,
        _: &AuthRequest,
        _: &AuthContext<S>,
    ) -> AuthResult<Option<AuthResponse>> {
        Ok(None)
    }
}
fn declaration(fields: impl IntoIterator<Item = (&'static str, UserFieldConfig)>) -> UserConfig {
    UserConfig {
        additional_fields: Some(
            fields
                .into_iter()
                .map(|(name, field)| (name.into(), field))
                .collect(),
        ),
    }
}
fn reference(model: &str, field: &str) -> UserFieldReference {
    UserFieldReference {
        model: model.into(),
        field: field.into(),
        ..Default::default()
    }
}

pub(super) async fn auth<S: AuthSchema>(
    raw: Arc<dyn AuthStore<S>>,
    native: bool,
    parent: Parent,
    case: Case,
    events: &Events,
    function: &FieldValue,
) -> AuthResult<BetterAuth<S>> {
    let mut options = OrganizationConfig::default();
    options.teams.enabled = true;
    if case == Case::ManyEmptySchema {
        options.schema.organization = UserConfig {
            additional_fields: Some(Default::default()),
        };
    } else if case == Case::FunctionHidden {
        options.schema.organization = declaration([(
            "name",
            UserFieldConfig {
                returned: Some(false),
                ..Default::default()
            },
        )]);
    }
    let mut parent_fields = UserConfig::default();
    if !case.reverse() {
        let events = events.clone();
        let name = format!("{}.organizationId", parent.model());
        let references = (!matches!(case, Case::NoRefs | Case::NoRefsEmpty)).then(|| {
            reference(
                "organization",
                if case == Case::Redirect { "slug" } else { "id" },
            )
        });
        let _ = parent_fields.fields_mut().insert(
            "organizationId".into(),
            UserFieldConfig {
                field_name: Some("role".into()),
                references,
                unique: Some(true),
                transform: Some(FieldTransforms {
                    output: Some(UserFieldTransform::new(move |value| {
                        events.push(&name, value.clone())?;
                        Ok(match case {
                            Case::Redirect => "slug-b".into(),
                            Case::NullProjection => FieldValue::Null,
                            _ => value,
                        })
                    })),
                    ..Default::default()
                }),
                ..Default::default()
            },
        );
    } else {
        let events = events.clone();
        let name = format!("{}.role", parent.model());
        let _ = parent_fields.fields_mut().insert(
            "role".into(),
            UserFieldConfig {
                transform: Some(FieldTransforms {
                    output: Some(UserFieldTransform::new(move |value| {
                        events.push(&name, value.clone())?;
                        Ok(value)
                    })),
                    ..Default::default()
                }),
                ..Default::default()
            },
        );
    }
    if matches!(case, Case::MultipleRefs | Case::MultipleRefsEmpty) {
        let _ = parent_fields.fields_mut().insert(
            "role".into(),
            UserFieldConfig {
                references: Some(reference("organization", "slug")),
                ..Default::default()
            },
        );
    }
    let name = {
        let (events, function) = (events.clone(), function.clone());
        UserFieldConfig {
            transform: Some(FieldTransforms {
                output: Some(UserFieldTransform::new(move |value| {
                    events.push("organization.name", value.clone())?;
                    if case.function() {
                        Ok(function.clone())
                    } else {
                        Ok(format!(
                            "visible:{}",
                            value.as_str().ok_or_else(|| AuthError::internal(
                                "Expected stored organization name"
                            ))?
                        )
                        .into())
                    }
                })),
                ..Default::default()
            }),
            ..Default::default()
        }
    };
    let mut organization = declaration([("name", name)]);
    if case.reverse() {
        let _ = organization.fields_mut().insert(
            "logo".into(),
            UserFieldConfig {
                references: Some(reference(parent.model(), "role")),
                unique: Some(case == Case::UniqueDuplicates),
                ..Default::default()
            },
        );
    }
    BetterAuth::new(config(native))
        .store_arc(raw)
        .plugin(OrganizationPlugin::with_config(options))
        .plugin(Fields(vec![
            (parent.role(), parent_fields),
            (EntityRole::Organization, organization),
        ]))
        .build()
        .await
}
