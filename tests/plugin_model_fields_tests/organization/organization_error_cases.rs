use super::*;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Case {
    TeamSession,
    SlugSession,
    TeamOrganization,
    MissingTeam,
    CreateSession,
    RemoveSession,
    RemoveOrganization,
    UpdateSession,
    UpdateOrganization,
    InvitationOrganization,
    OrgCreateSession,
    OrgCreateNoUser,
    OrgCreateMissingUser,
    OrgCreateDenied,
    OrgCreateLimit,
    OrgCreateDuplicate,
    SlugTaken,
    OrgUpdateMember,
    OrgUpdateDenied,
    OrgUpdateSlug,
    OrgDeleteDisabled,
    OrgDeleteDisabledSession,
    OrgDeleteSession,
    OrgDeleteEmpty,
    OrgDeleteMember,
    OrgDeleteDenied,
    OrgGetMissing,
    OrgGetMember,
    OrgFullMissing,
    OrgFullMember,
    OrgActiveMissing,
    OrgActiveMember,
    OrgLeaveMember,
    OrgLeaveOwner,
}

impl Case {
    pub(super) const ALL: &[Self] = &[
        Self::TeamSession,
        Self::SlugSession,
        Self::TeamOrganization,
        Self::MissingTeam,
        Self::CreateSession,
        Self::RemoveSession,
        Self::RemoveOrganization,
        Self::UpdateSession,
        Self::UpdateOrganization,
        Self::InvitationOrganization,
        Self::OrgCreateSession,
        Self::OrgCreateNoUser,
        Self::OrgCreateMissingUser,
        Self::OrgCreateDenied,
        Self::OrgCreateLimit,
        Self::OrgCreateDuplicate,
        Self::SlugTaken,
        Self::OrgUpdateMember,
        Self::OrgUpdateDenied,
        Self::OrgUpdateSlug,
        Self::OrgDeleteDisabled,
        Self::OrgDeleteDisabledSession,
        Self::OrgDeleteSession,
        Self::OrgDeleteEmpty,
        Self::OrgDeleteMember,
        Self::OrgDeleteDenied,
        Self::OrgGetMissing,
        Self::OrgGetMember,
        Self::OrgFullMissing,
        Self::OrgFullMember,
        Self::OrgActiveMissing,
        Self::OrgActiveMember,
        Self::OrgLeaveMember,
        Self::OrgLeaveOwner,
    ];

    pub(super) fn authenticated(self) -> bool {
        !matches!(
            self,
            Self::TeamSession
                | Self::SlugSession
                | Self::CreateSession
                | Self::RemoveSession
                | Self::RemoveOrganization
                | Self::UpdateSession
                | Self::OrgCreateSession
                | Self::OrgCreateNoUser
                | Self::OrgCreateMissingUser
                | Self::OrgDeleteSession
                | Self::OrgDeleteDisabledSession
        )
    }

    pub(super) fn headerless(self) -> bool {
        matches!(self, Self::OrgCreateNoUser | Self::OrgCreateMissingUser)
    }

    pub(super) fn clears_active(self) -> bool {
        matches!(
            self,
            Self::OrgGetMember | Self::OrgFullMember | Self::OrgActiveMember
        )
    }

    pub(super) fn query(self) -> Option<Value> {
        match self {
            Self::OrgGetMissing | Self::OrgFullMissing => Some(json!({"organizationId":"missing"})),
            Self::OrgGetMember | Self::OrgFullMember => {
                Some(json!({"organizationId":"source-parent"}))
            }
            _ => None,
        }
    }

    pub(super) fn request(self) -> (HttpMethod, &'static str, Option<Value>) {
        let (path, body) = match self {
            Self::TeamSession | Self::TeamOrganization => (
                "/organization/update-team",
                json!({"teamId":"missing", "data":{"name":"Updated"}}),
            ),
            Self::MissingTeam => (
                "/organization/update-team",
                json!({"teamId":"missing", "data":{"name":"Updated", "organizationId":"organization"}}),
            ),
            Self::SlugSession => ("/organization/check-slug", json!({"slug":"available"})),
            Self::CreateSession => (
                "/organization/create-team",
                json!({"name":"New", "organizationId":"organization"}),
            ),
            Self::RemoveSession => (
                "/organization/remove-team",
                json!({"teamId":"missing", "organizationId":"organization"}),
            ),
            Self::RemoveOrganization => ("/organization/remove-team", json!({"teamId":"missing"})),
            Self::UpdateSession | Self::UpdateOrganization => {
                ("/organization/update", json!({"data":{"name":"Updated"}}))
            }
            Self::InvitationOrganization => {
                return (HttpMethod::Get, "/organization/list-invitations", None);
            }
            Self::OrgCreateSession
            | Self::OrgCreateNoUser
            | Self::OrgCreateDenied
            | Self::OrgCreateLimit => (
                "/organization/create",
                json!({"name":"New", "slug":"available"}),
            ),
            Self::OrgCreateMissingUser => (
                "/organization/create",
                json!({"name":"New", "slug":"available", "userId":"missing"}),
            ),
            Self::OrgCreateDuplicate => (
                "/organization/create",
                json!({"name":"New", "slug":"organization"}),
            ),
            Self::SlugTaken => ("/organization/check-slug", json!({"slug":"organization"})),
            Self::OrgUpdateMember => (
                "/organization/update",
                json!({"organizationId":"source-parent", "data":{"name":"Updated"}}),
            ),
            Self::OrgUpdateDenied => (
                "/organization/update",
                json!({"organizationId":"organization", "data":{"name":"Updated"}}),
            ),
            Self::OrgUpdateSlug => (
                "/organization/update",
                json!({"organizationId":"organization", "data":{"slug":"other"}}),
            ),
            Self::OrgDeleteDisabled
            | Self::OrgDeleteDisabledSession
            | Self::OrgDeleteSession
            | Self::OrgDeleteDenied => (
                "/organization/delete",
                json!({"organizationId":"organization"}),
            ),
            Self::OrgDeleteEmpty => ("/organization/delete", json!({"organizationId":""})),
            Self::OrgDeleteMember => (
                "/organization/delete",
                json!({"organizationId":"source-parent"}),
            ),
            Self::OrgGetMissing | Self::OrgGetMember => {
                return (HttpMethod::Get, "/organization/get-organization", None);
            }
            Self::OrgFullMissing | Self::OrgFullMember => {
                return (HttpMethod::Get, "/organization/get-full-organization", None);
            }
            Self::OrgActiveMissing => (
                "/organization/set-active",
                json!({"organizationSlug":"missing"}),
            ),
            Self::OrgActiveMember => (
                "/organization/set-active",
                json!({"organizationId":"source-parent"}),
            ),
            Self::OrgLeaveMember => (
                "/organization/leave",
                json!({"organizationId":"source-parent"}),
            ),
            Self::OrgLeaveOwner => (
                "/organization/leave",
                json!({"organizationId":"organization"}),
            ),
        };
        (HttpMethod::Post, path, Some(body))
    }

    pub(super) fn expected(self) -> (u16, FieldValue) {
        let (status, message, code) = match self {
            Self::TeamSession | Self::SlugSession => (401, "Unauthorized", Some("UNAUTHORIZED")),
            Self::TeamOrganization | Self::RemoveOrganization => (
                400,
                "No active organization",
                Some("NO_ACTIVE_ORGANIZATION"),
            ),
            Self::MissingTeam => (400, "Team not found", Some("TEAM_NOT_FOUND")),
            Self::CreateSession
            | Self::RemoveSession
            | Self::OrgCreateSession
            | Self::OrgCreateNoUser
            | Self::OrgCreateMissingUser
            | Self::OrgDeleteSession => return (401, FieldValue::Undefined),
            Self::UpdateSession => (401, "User not found", None),
            Self::UpdateOrganization
            | Self::OrgDeleteEmpty
            | Self::OrgGetMissing
            | Self::OrgFullMissing
            | Self::OrgActiveMissing => (
                400,
                "Organization not found",
                Some("ORGANIZATION_NOT_FOUND"),
            ),
            Self::InvitationOrganization => (400, "Organization ID is required", None),
            Self::OrgCreateDenied => (
                403,
                "You are not allowed to create a new organization",
                Some("YOU_ARE_NOT_ALLOWED_TO_CREATE_A_NEW_ORGANIZATION"),
            ),
            Self::OrgCreateLimit => (
                403,
                "You have reached the maximum number of organizations",
                Some("YOU_HAVE_REACHED_THE_MAXIMUM_NUMBER_OF_ORGANIZATIONS"),
            ),
            Self::OrgCreateDuplicate => (
                400,
                "Organization already exists",
                Some("ORGANIZATION_ALREADY_EXISTS"),
            ),
            Self::SlugTaken | Self::OrgUpdateSlug => (
                400,
                "Organization slug already taken",
                Some("ORGANIZATION_SLUG_ALREADY_TAKEN"),
            ),
            Self::OrgUpdateMember | Self::OrgDeleteMember => (
                400,
                "User is not a member of the organization",
                Some("USER_IS_NOT_A_MEMBER_OF_THE_ORGANIZATION"),
            ),
            Self::OrgUpdateDenied => (
                403,
                "You are not allowed to update this organization",
                Some("YOU_ARE_NOT_ALLOWED_TO_UPDATE_THIS_ORGANIZATION"),
            ),
            Self::OrgDeleteDisabled | Self::OrgDeleteDisabledSession => (
                404,
                "Organization deletion is disabled",
                Some("ORGANIZATION_DELETION_DISABLED"),
            ),
            Self::OrgDeleteDenied => (
                403,
                "You are not allowed to delete this organization",
                Some("YOU_ARE_NOT_ALLOWED_TO_DELETE_THIS_ORGANIZATION"),
            ),
            Self::OrgGetMember | Self::OrgFullMember | Self::OrgActiveMember => (
                403,
                "User is not a member of the organization",
                Some("USER_IS_NOT_A_MEMBER_OF_THE_ORGANIZATION"),
            ),
            Self::OrgLeaveMember => (400, "Member not found", Some("MEMBER_NOT_FOUND")),
            Self::OrgLeaveOwner => (
                400,
                "You cannot leave the organization as the only owner",
                Some("YOU_CANNOT_LEAVE_THE_ORGANIZATION_AS_THE_ONLY_OWNER"),
            ),
        };
        let mut body = FieldMap::from([("message".into(), message.into())]);
        if let Some(code) = code {
            let _ = body.insert("code".into(), code.into());
        }
        (status, body.into())
    }
}
