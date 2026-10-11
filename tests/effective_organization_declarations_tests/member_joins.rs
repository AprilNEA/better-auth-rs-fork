use super::*;
use better_auth_core::store::ListOrganizationMembersParams;

fn snapshot(store: &EphemeralStore) -> AuthResult<FieldMap> {
    [
        (EntityRole::User, "user"),
        (EntityRole::Session, "session"),
        (EntityRole::Account, "account"),
        (EntityRole::Verification, "verification"),
        (EntityRole::Member, "member"),
    ]
    .into_iter()
    .map(|(role, name)| {
        Ok((
            name.into(),
            store
                .storage_rows(role)?
                .into_iter()
                .map(FieldValue::from)
                .collect::<Vec<_>>()
                .into(),
        ))
    })
    .collect()
}

#[tokio::test]
async fn explicit_member_declarations_do_not_restore_filters_or_user_references() -> AuthResult<()>
{
    for partial in [false, true] {
        for joins in [false, true] {
            let mut config = config();
            config.advanced.database.joins = Some(joins);
            let raw = EphemeralStore::new(Arc::new(config.clone()));
            let empty = snapshot(&raw)?;
            let callbacks = Callbacks::default();
            let mut fields = callbacks.fields(partial);
            if let Some(field) = fields.fields_mut().get_mut("organizationId") {
                field.field_name = Some("organization_id".into());
            }
            let auth = BetterAuth::new(config)
                .store(raw.clone())
                .plugin(Declaration(EntityRole::Member, fields))
                .build()
                .await?;
            let error = auth
                .store()
                .get_member_by_id_with_user(ID)
                .await
                .err()
                .ok_or_else(|| {
                    AuthError::internal("Expected the missing Member/User foreign key")
                })?;
            assert!(
                matches!(&error, AuthError::Config(message) if message == "No foreign key found for model user and base model member while performing join operation."),
                "{error}"
            );
            assert!(callbacks.take()?.is_empty());
            assert_eq!(snapshot(&raw)?, empty);
            let error = auth
                .store()
                .query_organization_members(&ListOrganizationMembersParams {
                    organization_id: "source".into(),
                    filter_field: Some("userId".into()),
                    filter_value: Some("owner".into()),
                    ..Default::default()
                })
                .await
                .err()
                .ok_or_else(|| AuthError::internal("Expected the undeclared Member filter"))?;
            let expected = if partial {
                "Field userId not found in model member"
            } else {
                "Field organizationId not found in model member"
            };
            assert!(
                matches!(&error, AuthError::Config(message) if message == expected),
                "{error}"
            );
            assert!(callbacks.take()?.is_empty());
            assert_eq!(snapshot(&raw)?, empty);
        }
    }
    Ok(())
}
