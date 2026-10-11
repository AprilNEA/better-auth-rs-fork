#![expect(
    clippy::panic_in_result_fn,
    reason = "The paired contract asserts exact error timing, callback order, complete results, and unchanged storage"
)]

use super::{Trace, date, record, take_trace};
use better_auth_core::{
    AuthConfig, AuthError, AuthRecordFields, AuthResult, AuthStore, CreateMember, CreateUser,
    FieldMap, FieldValue, ListUsersParams,
    id::{IdGeneration, IdGenerator},
    organization_fields::OrganizationFields,
    store::{
        EphemeralStore, ListOrganizationMembersParams, MemberStore, OrganizationStore,
        RuntimeStore, StatelessSchema, UserStore, schema::EntityRole,
    },
    user_fields::{FieldTransforms, UserFieldConfig, UserFieldTransform, UserFieldType},
};
use std::sync::Arc;

#[derive(Clone, Copy, Debug)]
enum Model {
    User,
    Member,
}

impl Model {
    fn field(self) -> &'static str {
        match self {
            Self::User => "name",
            Self::Member => "role",
        }
    }
}

fn snapshot(store: &EphemeralStore) -> AuthResult<Vec<Vec<FieldMap>>> {
    [
        EntityRole::User,
        EntityRole::Session,
        EntityRole::Account,
        EntityRole::Verification,
        EntityRole::Organization,
        EntityRole::Member,
        EntityRole::Invitation,
        EntityRole::Team,
        EntityRole::TeamMember,
        EntityRole::OrganizationRole,
    ]
    .into_iter()
    .map(|role| store.storage_rows(role))
    .collect()
}

async fn seed(model: Model, populated: bool) -> AuthResult<EphemeralStore> {
    let mut config = AuthConfig::default();
    config.advanced.database.generate_id = Some(IdGeneration::Custom(IdGenerator::new(|_| {
        Ok(Some("seed".into()))
    })));
    let writer = EphemeralStore::new(Arc::new(config));
    if populated {
        match model {
            Model::User => {
                let _ = writer
                    .create_user(CreateUser {
                        id: Some("seed".into()),
                        created_at: Some(date()),
                        updated_at: Some(date()),
                        ..CreateUser::new()
                            .with_name("Middle")
                            .with_email("seed@memory-where.test")
                    })
                    .await?;
            }
            Model::Member => {
                let mut fields = OrganizationFields::default();
                let _ = fields.member.fields_mut().insert(
                    "createdAt".into(),
                    UserFieldConfig {
                        field_type: UserFieldType::Date,
                        transform: Some(FieldTransforms {
                            input: Some(UserFieldTransform::new(|_| Ok(date().into()))),
                            ..Default::default()
                        }),
                        ..Default::default()
                    },
                );
                writer.configure_organization_fields(fields)?;
                let _ = writer
                    .create_member(CreateMember {
                        organization_id: "other-org".into(),
                        user_id: "owner".into(),
                        role: "Middle".into(),
                        additional_fields: FieldMap::new(),
                    })
                    .await?;
            }
        }
    }
    Ok(writer)
}

fn reader(
    writer: &EphemeralStore,
    model: Model,
    field_type: UserFieldType,
    trace: &Trace,
) -> AuthResult<Arc<dyn AuthStore<StatelessSchema>>> {
    let input = trace.clone();
    let output = trace.clone();
    let declaration = UserFieldConfig {
        field_type,
        transform: Some(FieldTransforms {
            input: Some(UserFieldTransform::new(move |value| {
                record(&input, "input")?;
                Ok(value)
            })),
            output: Some(UserFieldTransform::new(move |value| {
                record(&output, "output")?;
                Ok(value)
            })),
        }),
        ..Default::default()
    };
    let mut config = AuthConfig::default();
    if matches!(model, Model::User) {
        let _ = config
            .user
            .fields_mut()
            .insert(model.field().into(), declaration.clone());
    }
    // The query runtime must start with fresh ID state after the seed writes.
    let store = writer.with_runtime(Arc::new(config), Vec::new(), Default::default())?;
    if matches!(model, Model::Member) {
        let mut fields = OrganizationFields::default();
        let _ = fields
            .member
            .fields_mut()
            .insert(model.field().into(), declaration);
        store.configure_organization_fields(fields)?;
    }
    Ok(store)
}

struct Filter {
    field: &'static str,
    operator: &'static str,
    value: FieldValue,
}

async fn query_excluded_rows(
    store: &dyn AuthStore<StatelessSchema>,
    model: Model,
    filter: Filter,
) -> AuthResult<(Vec<FieldMap>, usize)> {
    match model {
        Model::User => {
            let (rows, total) = store
                .list_users(ListUsersParams {
                    search_field: Some("email".into()),
                    search_value: Some("absent".into()),
                    search_operator: Some("eq".into()),
                    filter_field: Some(filter.field.into()),
                    filter_operator: Some(filter.operator.into()),
                    filter_value: Some(filter.value),
                    ..Default::default()
                })
                .await?;
            Ok((
                rows.iter()
                    .map(AuthRecordFields::field_values)
                    .collect::<AuthResult<Vec<_>>>()?,
                total,
            ))
        }
        Model::Member => {
            let (rows, total) = store
                .query_organization_members(&ListOrganizationMembersParams {
                    organization_id: "target-org".into(),
                    filter_field: Some(filter.field.into()),
                    filter_operator: Some(filter.operator.into()),
                    filter_value: Some(filter.value),
                    ..Default::default()
                })
                .await?;
            Ok((
                rows.iter()
                    .map(AuthRecordFields::field_values)
                    .collect::<AuthResult<Vec<_>>>()?,
                total,
            ))
        }
    }
}

#[tokio::test]
async fn memory_membership_validates_raw_in_before_binding_and_other_operands_per_row()
-> AuthResult<()> {
    for model in [Model::User, Model::Member] {
        for populated in [false, true] {
            for (json, operator) in [
                (false, "in"),
                (false, "not_in"),
                (true, "in"),
                (true, "not_in"),
            ] {
                let writer = seed(model, populated).await?;
                let before = snapshot(&writer)?;
                let trace = Trace::default();
                let store = reader(
                    &writer,
                    model,
                    if json {
                        UserFieldType::Json
                    } else {
                        UserFieldType::String
                    },
                    &trace,
                )?;
                let result = query_excluded_rows(
                    store.as_ref(),
                    model,
                    Filter {
                        field: model.field(),
                        operator,
                        value: if json {
                            vec![FieldValue::from("Middle")].into()
                        } else {
                            "Middle".into()
                        },
                    },
                )
                .await;
                if !json && operator == "in" {
                    assert!(
                        matches!(&result, Err(AuthError::Config(message)) if message == "Value must be an array"),
                        "{model:?}, {populated}, {json}, {operator}: {result:?}"
                    );
                } else if populated {
                    assert!(
                        matches!(&result, Err(AuthError::Internal(message)) if message == "Value must be an array"),
                        "{model:?}, {populated}, {json}, {operator}: {result:?}"
                    );
                } else {
                    assert_eq!(result?, (Vec::new(), 0));
                }
                assert_eq!(take_trace(&trace)?, Vec::<&str>::new());
                assert_eq!(snapshot(&writer)?, before);
            }
        }
        let writer = seed(model, false).await?;
        let before = snapshot(&writer)?;
        let trace = Trace::default();
        let store = reader(&writer, model, UserFieldType::String, &trace)?;
        let result = query_excluded_rows(
            store.as_ref(),
            model,
            Filter {
                field: "unknown",
                operator: "in",
                value: "Middle".into(),
            },
        )
        .await;
        assert!(
            matches!(&result, Err(AuthError::Config(message)) if message == "Value must be an array"),
            "{model:?}: {result:?}"
        );
        assert_eq!(take_trace(&trace)?, Vec::<&str>::new());
        assert_eq!(snapshot(&writer)?, before);
    }
    Ok(())
}
