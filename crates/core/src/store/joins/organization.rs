use super::{JoinValue, OrganizationDetails};
use crate::organization_fields::OrganizationFields;
use crate::user_fields::UserConfig;
use crate::{AuthError, AuthRecordFields, AuthResult, FieldMap, FieldValue, MemberUserView};

fn public_page(rows: Vec<FieldMap>, schema: &UserConfig) -> AuthResult<FieldValue> {
    rows.into_iter()
        .map(|row| schema.filter_output_value(row.into()))
        .collect::<AuthResult<Vec<_>>>()
        .map(FieldValue::from)
}

impl OrganizationDetails {
    /// Apply public cloning, owner lookup, and relationship consumption in upstream order.
    pub fn into_public_value(self, schema: &OrganizationFields) -> AuthResult<FieldValue> {
        let mut organization = self.organization;
        for name in ["invitation", "member", "team"] {
            let _ = organization.shift_remove(name);
        }
        let members = self
            .members
            .into_iter()
            .map(|member| {
                let owner = member.get("userId").unwrap_or(&FieldValue::Undefined);
                let user = self
                    .users
                    .iter()
                    .rev()
                    .find(|user| user.id.field_value().same_value_zero(owner))
                    .ok_or_else(|| {
                        AuthError::internal("Unexpected error: User not found for member")
                    })?;
                let mut member = schema
                    .member
                    .filter_output_value(member.into())?
                    .enumerable_fields()?;
                let _ = member.insert(
                    "user".into(),
                    MemberUserView::from_user(user).field_values()?.into(),
                );
                Ok(FieldValue::from(member))
            })
            .collect::<AuthResult<Vec<_>>>()?;
        let mut organization = schema
            .organization
            .filter_output_value(organization.into())?
            .enumerable_fields()?;
        let invitations = public_page(
            self.invitations.into_required_page("invitations")?,
            &schema.invitation,
        )?;
        let teams = match self.teams {
            None | Some(JoinValue::One(None)) => FieldValue::Undefined,
            Some(JoinValue::One(Some(_))) => {
                return Err(AuthError::type_error("teams?.map is not a function"));
            }
            Some(JoinValue::Many(rows)) => public_page(rows, &schema.team)?,
        };
        let _ = organization.insert("invitations".into(), invitations);
        let _ = organization.insert("members".into(), members.into());
        let _ = organization.insert("teams".into(), teams);
        Ok(organization.into())
    }
}

#[cfg(test)]
#[expect(
    clippy::panic_in_result_fn,
    reason = "Contract assertions retain exact values and propagate setup errors."
)]
mod tests {
    use super::*;
    use crate::user_fields::{UserFieldConfig, UserFieldFactory};
    use crate::{FieldDate, FieldFunction, FromFieldMap, wire::UserView};
    use std::sync::Arc;

    fn function() -> FieldValue {
        let callback: UserFieldFactory = Arc::new(|| Ok(FieldValue::Undefined));
        FieldFunction::from(callback).into()
    }

    fn details() -> AuthResult<OrganizationDetails> {
        Ok(OrganizationDetails {
            organization: [("id".into(), "organization".into())].into(),
            invitations: JoinValue::Many(Vec::new()),
            members: vec![
                [
                    ("id".into(), "member".into()),
                    ("userId".into(), "owner".into()),
                ]
                .into(),
            ],
            users: vec![UserView::from_field_values(
                [
                    ("id".into(), "owner".into()),
                    ("name".into(), "Owner".into()),
                ]
                .into(),
            )?],
            teams: None,
        })
    }

    #[test]
    fn member_clone_fails_before_later_missing_owner_and_hidden_field_filter() -> AuthResult<()> {
        let mut details = details()?;
        details.members = vec![
            [
                ("userId".into(), "owner".into()),
                ("hidden".into(), function()),
            ]
            .into(),
            [("userId".into(), "missing".into())].into(),
        ];
        let mut schema = OrganizationFields::default();
        let _ = schema.member.fields_mut().insert(
            "hidden".into(),
            UserFieldConfig {
                returned: Some(false),
                ..Default::default()
            },
        );
        assert!(matches!(
            details.into_public_value(&schema),
            Err(AuthError::DataClone)
        ));
        Ok(())
    }

    #[test]
    fn parent_and_invitation_clone_errors_precede_later_cardinality_errors() -> AuthResult<()> {
        for parent_failure in [false, true] {
            let mut details = details()?;
            let mut schema = OrganizationFields::default();
            if parent_failure {
                let _ = details.organization.insert("hidden".into(), function());
                schema.organization.additional_fields = Some(Default::default());
                details.invitations = JoinValue::One(None);
            } else {
                details.invitations = JoinValue::Many(vec![[("hidden".into(), function())].into()]);
                schema.invitation.additional_fields = Some(Default::default());
            }
            details.teams = Some(JoinValue::One(Some(FieldMap::new())));
            assert!(matches!(
                details.into_public_value(&schema),
                Err(AuthError::DataClone)
            ));
        }
        Ok(())
    }

    #[test]
    fn public_output_preserves_order_identity_and_last_matching_user() -> AuthResult<()> {
        let mut details = details()?;
        let callback = function();
        let date = FieldValue::from(FieldDate::from_milliseconds(1_893_456_000_000.0));
        let _ = details
            .organization
            .insert("createdAt".into(), date.clone());
        details.users.push(UserView::from_field_values(
            [
                ("id".into(), "owner".into()),
                ("name".into(), callback.clone()),
            ]
            .into(),
        )?);
        let output = details.into_public_value(&OrganizationFields::default())?;
        assert_eq!(
            output
                .enumerable_fields()?
                .keys()
                .map(String::as_str)
                .collect::<Vec<_>>(),
            ["id", "createdAt", "invitations", "members", "teams"]
        );
        assert!(output.model_property("createdAt")?.strict_equals(&date));
        let members = output.model_property("members")?;
        let member = members
            .as_array()
            .map(|rows| rows.first())
            .transpose()?
            .flatten()
            .ok_or_else(|| AuthError::internal("Expected public member"))?;
        let user = member.model_property("user")?;
        assert!(user.model_property("name")?.strict_equals(&callback));
        assert!(user.enumerable_fields()?.contains_key("image"));
        assert!(user.model_property("image")?.is_undefined());
        assert!(output.model_property("teams")?.is_undefined());
        let json = output
            .json()?
            .ok_or_else(|| AuthError::internal("Expected JSON organization"))?;
        assert!(json.get("teams").is_none());
        Ok(())
    }
}
