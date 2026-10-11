use super::{
    AcceptInvitationResponse, BasicMemberResponse, CreateOrganizationResponse,
    CreatedOrganizationResponse, GetActiveMemberRoleResponse, GetInvitationResponse,
    ListMembersResponse, MemberResponse, RemovedMemberResponse, UserInvitationResponse,
};
use better_auth_core::wire::InvitationView;
use better_auth_core::{AuthRecordFields, AuthResult, FieldMap, FieldValue, FromFieldMap};
use serde::Serialize;

macro_rules! record {
    ($record:ty, [$($field:ident => $name:literal),* $(,)?]) => {
        impl AuthRecordFields for $record {
            fn field_values(&self) -> AuthResult<FieldMap> {
                let mut fields = FieldMap::from_iter([
                    $(($name.into(), self.$field.field_value())),*
                ]);
                fields.extend(self.additional_fields.clone());
                Ok(fields)
            }
        }
    };
}

record!(CreatedOrganizationResponse, [
    id => "id",
    name => "name",
    slug => "slug",
    logo => "logo",
    metadata => "metadata",
    created_at => "createdAt",
]);

impl AuthRecordFields for MemberResponse {
    fn field_values(&self) -> AuthResult<FieldMap> {
        let mut fields = self.member.field_values()?;
        let _ = fields.insert("user".into(), self.user.field_values()?.into());
        Ok(fields)
    }
}

impl Serialize for MemberResponse {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        better_auth_core::field_value::serde::map::serialize(
            &self.field_values().map_err(serde::ser::Error::custom)?,
            serializer,
        )
    }
}

impl MemberResponse {
    pub(crate) fn into_member(self) -> AuthResult<BasicMemberResponse> {
        BasicMemberResponse::from_field_values(self.field_values()?)
    }
}

impl AuthRecordFields for ListMembersResponse {
    fn field_values(&self) -> AuthResult<FieldMap> {
        let members = self
            .members
            .iter()
            .map(|member| member.field_values().map(FieldValue::from))
            .collect::<AuthResult<Vec<_>>>()?;
        Ok([
            ("members".into(), members.into()),
            ("total".into(), FieldValue::Number(self.total as f64)),
        ]
        .into())
    }
}

impl AuthRecordFields for GetActiveMemberRoleResponse {
    fn field_values(&self) -> AuthResult<FieldMap> {
        Ok([("role".into(), self.role.field_value())].into())
    }
}

impl AuthRecordFields for RemovedMemberResponse {
    fn field_values(&self) -> AuthResult<FieldMap> {
        Ok([("member".into(), self.member.field_values()?.into())].into())
    }
}

impl<O: Serialize + AuthRecordFields, M: Serialize + AuthRecordFields> AuthRecordFields
    for CreateOrganizationResponse<O, M>
{
    fn field_values(&self) -> AuthResult<FieldMap> {
        let mut fields = self.organization.field_values()?;
        let members = self
            .members
            .iter()
            .map(|member| member.field_values().map(FieldValue::from))
            .collect::<AuthResult<Vec<_>>>()?;
        let _ = fields.insert("members".into(), members.into());
        Ok(fields)
    }
}

impl<I: Serialize + AuthRecordFields> AuthRecordFields for GetInvitationResponse<I> {
    fn field_values(&self) -> AuthResult<FieldMap> {
        let mut fields = self.invitation.field_values()?;
        let _ = fields.insert(
            "organizationName".into(),
            self.organization_name.field_value(),
        );
        let _ = fields.insert(
            "organizationSlug".into(),
            self.organization_slug.field_value(),
        );
        let _ = fields.insert("inviterEmail".into(), self.inviter_email.field_value());
        Ok(fields)
    }
}

impl<I: Serialize + AuthRecordFields> AuthRecordFields for UserInvitationResponse<I> {
    fn field_values(&self) -> AuthResult<FieldMap> {
        let mut fields = self.invitation.field_values()?;
        let _ = fields.insert(
            "organizationName".into(),
            self.organization_name.field_value(),
        );
        Ok(fields)
    }
}

impl AuthRecordFields for AcceptInvitationResponse<InvitationView, BasicMemberResponse> {
    fn field_values(&self) -> AuthResult<FieldMap> {
        Ok([
            ("invitation".into(), self.invitation.field_values()?.into()),
            ("member".into(), self.member.field_values()?.into()),
        ]
        .into())
    }
}

impl AuthRecordFields
    for AcceptInvitationResponse<Option<InvitationView>, Option<BasicMemberResponse>>
{
    fn field_values(&self) -> AuthResult<FieldMap> {
        let invitation = self
            .invitation
            .as_ref()
            .map(AuthRecordFields::field_values)
            .transpose()?;
        let member = self
            .member
            .as_ref()
            .map(AuthRecordFields::field_values)
            .transpose()?;
        Ok([
            (
                "invitation".into(),
                invitation.map(FieldValue::from).unwrap_or(FieldValue::Null),
            ),
            (
                "member".into(),
                member.map(FieldValue::from).unwrap_or(FieldValue::Null),
            ),
        ]
        .into())
    }
}
