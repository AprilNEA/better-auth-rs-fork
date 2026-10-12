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
    PermissionMember,
    InvitationSession,
    InvitationMember,
    GetInvitationSession,
    GetInvitationMissing,
    GetInvitationEmpty,
    CancelInvitationMissing,
    CancelInvitationMember,
    CancelInvitationDenied,
    InviteRoleUnknown,
    MemberRoleUnknown,
    MemberRoleEmpty,
    MemberRoleEmptyBeforeOrganization,
    MemberRoleEmptyArray,
    MemberRoleWhitespace,
    MemberRoleArrayWithoutOrganization,
    MemberUpdateMissing,
    MemberUpdateHookMissing,
    RoleCreateMissingPermissions,
    RoleUpdateMissingPermissions,
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
        Self::PermissionMember,
        Self::InvitationSession,
        Self::InvitationMember,
        Self::GetInvitationSession,
        Self::GetInvitationMissing,
        Self::GetInvitationEmpty,
        Self::CancelInvitationMissing,
        Self::CancelInvitationMember,
        Self::CancelInvitationDenied,
        Self::InviteRoleUnknown,
        Self::MemberRoleUnknown,
        Self::MemberRoleEmpty,
        Self::MemberRoleEmptyBeforeOrganization,
        Self::MemberRoleEmptyArray,
        Self::MemberRoleWhitespace,
        Self::MemberRoleArrayWithoutOrganization,
        Self::MemberUpdateMissing,
        Self::MemberUpdateHookMissing,
        Self::RoleCreateMissingPermissions,
        Self::RoleUpdateMissingPermissions,
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
                | Self::InvitationSession
                | Self::GetInvitationSession
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

    pub(super) fn member_target(self) -> bool {
        matches!(
            self,
            Self::MemberRoleUnknown
                | Self::MemberRoleEmpty
                | Self::MemberRoleEmptyBeforeOrganization
                | Self::MemberRoleEmptyArray
                | Self::MemberRoleWhitespace
                | Self::MemberRoleArrayWithoutOrganization
                | Self::MemberUpdateMissing
                | Self::MemberUpdateHookMissing
        )
    }

    pub(super) fn removes_target(self) -> bool {
        matches!(
            self,
            Self::MemberUpdateMissing | Self::MemberUpdateHookMissing
        )
    }

    pub(super) fn role_permissions(self) -> bool {
        matches!(
            self,
            Self::RoleCreateMissingPermissions | Self::RoleUpdateMissingPermissions
        )
    }

    pub(super) fn query(self) -> Option<Value> {
        match self {
            Self::GetInvitationSession | Self::GetInvitationMissing => {
                Some(json!({"id":"missing"}))
            }
            Self::GetInvitationEmpty => Some(json!({"id":""})),
            Self::InvitationMember => Some(json!({"organizationId":"source-parent"})),
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
            Self::InvitationOrganization | Self::InvitationSession | Self::InvitationMember => {
                return (HttpMethod::Get, "/organization/list-invitations", None);
            }
            Self::GetInvitationSession | Self::GetInvitationMissing | Self::GetInvitationEmpty => {
                return (HttpMethod::Get, "/organization/get-invitation", None);
            }
            Self::PermissionMember => (
                "/organization/has-permission",
                json!({"organizationId":"source-parent", "permissions":{"organization":["update"]}}),
            ),
            Self::CancelInvitationMissing => (
                "/organization/cancel-invitation",
                json!({"invitationId":"missing"}),
            ),
            Self::CancelInvitationMember | Self::CancelInvitationDenied => (
                "/organization/cancel-invitation",
                json!({"invitationId":"invitation-a"}),
            ),
            Self::InviteRoleUnknown => (
                "/organization/invite-member",
                json!({"organizationId":"organization", "email":"new@fields.test", "role":"unknown"}),
            ),
            Self::MemberRoleUnknown => (
                "/organization/update-member-role",
                json!({"organizationId":"organization", "memberId":"target-member", "role":"unknown"}),
            ),
            Self::MemberRoleEmpty => (
                "/organization/update-member-role",
                json!({"organizationId":"organization", "memberId":"target-member", "role":""}),
            ),
            Self::MemberRoleEmptyBeforeOrganization => (
                "/organization/update-member-role",
                json!({"memberId":"target-member", "role":""}),
            ),
            Self::MemberRoleEmptyArray => (
                "/organization/update-member-role",
                json!({"organizationId":"organization", "memberId":"target-member", "role":[]}),
            ),
            Self::MemberRoleWhitespace => (
                "/organization/update-member-role",
                json!({"organizationId":"organization", "memberId":"target-member", "role":" ,  , "}),
            ),
            Self::MemberRoleArrayWithoutOrganization => (
                "/organization/update-member-role",
                json!({"memberId":"target-member", "role":[]}),
            ),
            Self::MemberUpdateMissing | Self::MemberUpdateHookMissing => (
                "/organization/update-member-role",
                json!({"organizationId":"organization", "memberId":"target-member", "role":"admin"}),
            ),
            Self::RoleCreateMissingPermissions => (
                "/organization/create-role",
                json!({"organizationId":"organization", "role":"custom", "permission":{"organization":["delete","update"]}}),
            ),
            Self::RoleUpdateMissingPermissions => (
                "/organization/update-role",
                json!({"organizationId":"organization", "roleName":"custom", "data":{"permission":{"organization":["delete","update"]}}}),
            ),
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

    pub(super) fn expected(self) -> (&'static str, u16, FieldValue) {
        if self == Self::MemberRoleUnknown {
            return (
                "BAD_REQUEST",
                400,
                FieldMap::from([
                    ("code".into(), "ROLE_NOT_FOUND".into()),
                    ("message".into(), "ROLE_NOT_FOUND: unknown".into()),
                ])
                .into(),
            );
        }
        if self.role_permissions() {
            let (code, message) = if self == Self::RoleCreateMissingPermissions {
                (
                    "YOU_ARE_NOT_ALLOWED_TO_CREATE_A_ROLE",
                    "You are not allowed to create a role",
                )
            } else {
                (
                    "YOU_ARE_NOT_ALLOWED_TO_UPDATE_A_ROLE",
                    "You are not allowed to update a role",
                )
            };
            return (
                "FORBIDDEN",
                403,
                FieldMap::from([
                    ("message".into(), message.into()),
                    ("code".into(), code.into()),
                    (
                        "missingPermissions".into(),
                        vec![
                            FieldValue::from("organization:delete"),
                            FieldValue::from("organization:update"),
                        ]
                        .into(),
                    ),
                ])
                .into(),
            );
        }
        let (name, status, message, code) = match self {
            Self::InvitationSession | Self::TeamSession | Self::SlugSession => {
                ("UNAUTHORIZED", 401, "Unauthorized", Some("UNAUTHORIZED"))
            }
            Self::MemberRoleArrayWithoutOrganization
            | Self::TeamOrganization
            | Self::RemoveOrganization => (
                "BAD_REQUEST",
                400,
                "No active organization",
                Some("NO_ACTIVE_ORGANIZATION"),
            ),
            Self::MissingTeam => ("BAD_REQUEST", 400, "Team not found", Some("TEAM_NOT_FOUND")),
            Self::CreateSession
            | Self::RemoveSession
            | Self::OrgCreateSession
            | Self::OrgCreateNoUser
            | Self::OrgCreateMissingUser
            | Self::OrgDeleteSession => return ("UNAUTHORIZED", 401, FieldValue::Undefined),
            Self::UpdateSession => ("UNAUTHORIZED", 401, "User not found", None),
            Self::GetInvitationSession => ("UNAUTHORIZED", 401, "Not authenticated", None),
            Self::PermissionMember => (
                "UNAUTHORIZED",
                401,
                "User is not a member of the organization",
                Some("USER_IS_NOT_A_MEMBER_OF_THE_ORGANIZATION"),
            ),
            Self::InvitationMember => (
                "FORBIDDEN",
                403,
                "You are not a member of this organization",
                None,
            ),
            Self::GetInvitationMissing | Self::GetInvitationEmpty => {
                ("BAD_REQUEST", 400, "Invitation not found!", None)
            }
            Self::CancelInvitationMissing => (
                "BAD_REQUEST",
                400,
                "Invitation not found",
                Some("INVITATION_NOT_FOUND"),
            ),
            Self::CancelInvitationMember
            | Self::MemberUpdateMissing
            | Self::MemberUpdateHookMissing => (
                "BAD_REQUEST",
                400,
                "Member not found",
                Some("MEMBER_NOT_FOUND"),
            ),
            Self::CancelInvitationDenied => (
                "FORBIDDEN",
                403,
                "You are not allowed to cancel this invitation",
                Some("YOU_ARE_NOT_ALLOWED_TO_CANCEL_THIS_INVITATION"),
            ),
            Self::InviteRoleUnknown => ("BAD_REQUEST", 400, "ROLE_NOT_FOUND: unknown", None),
            Self::MemberRoleEmpty
            | Self::MemberRoleEmptyBeforeOrganization
            | Self::MemberRoleEmptyArray
            | Self::MemberRoleWhitespace => return ("BAD_REQUEST", 400, FieldValue::Undefined),
            Self::MemberRoleUnknown
            | Self::RoleCreateMissingPermissions
            | Self::RoleUpdateMissingPermissions => {
                unreachable!("Explicit ordered bodies returned above")
            }
            Self::UpdateOrganization
            | Self::OrgDeleteEmpty
            | Self::OrgGetMissing
            | Self::OrgFullMissing
            | Self::OrgActiveMissing => (
                "BAD_REQUEST",
                400,
                "Organization not found",
                Some("ORGANIZATION_NOT_FOUND"),
            ),
            Self::InvitationOrganization => {
                ("BAD_REQUEST", 400, "Organization ID is required", None)
            }
            Self::OrgCreateDenied => (
                "FORBIDDEN",
                403,
                "You are not allowed to create a new organization",
                Some("YOU_ARE_NOT_ALLOWED_TO_CREATE_A_NEW_ORGANIZATION"),
            ),
            Self::OrgCreateLimit => (
                "FORBIDDEN",
                403,
                "You have reached the maximum number of organizations",
                Some("YOU_HAVE_REACHED_THE_MAXIMUM_NUMBER_OF_ORGANIZATIONS"),
            ),
            Self::OrgCreateDuplicate => (
                "BAD_REQUEST",
                400,
                "Organization already exists",
                Some("ORGANIZATION_ALREADY_EXISTS"),
            ),
            Self::SlugTaken | Self::OrgUpdateSlug => (
                "BAD_REQUEST",
                400,
                "Organization slug already taken",
                Some("ORGANIZATION_SLUG_ALREADY_TAKEN"),
            ),
            Self::OrgUpdateMember | Self::OrgDeleteMember => (
                "BAD_REQUEST",
                400,
                "User is not a member of the organization",
                Some("USER_IS_NOT_A_MEMBER_OF_THE_ORGANIZATION"),
            ),
            Self::OrgUpdateDenied => (
                "FORBIDDEN",
                403,
                "You are not allowed to update this organization",
                Some("YOU_ARE_NOT_ALLOWED_TO_UPDATE_THIS_ORGANIZATION"),
            ),
            Self::OrgDeleteDisabled | Self::OrgDeleteDisabledSession => (
                "NOT_FOUND",
                404,
                "Organization deletion is disabled",
                Some("ORGANIZATION_DELETION_DISABLED"),
            ),
            Self::OrgDeleteDenied => (
                "FORBIDDEN",
                403,
                "You are not allowed to delete this organization",
                Some("YOU_ARE_NOT_ALLOWED_TO_DELETE_THIS_ORGANIZATION"),
            ),
            Self::OrgGetMember | Self::OrgFullMember | Self::OrgActiveMember => (
                "FORBIDDEN",
                403,
                "User is not a member of the organization",
                Some("USER_IS_NOT_A_MEMBER_OF_THE_ORGANIZATION"),
            ),
            Self::OrgLeaveMember => (
                "BAD_REQUEST",
                400,
                "Member not found",
                Some("MEMBER_NOT_FOUND"),
            ),
            Self::OrgLeaveOwner => (
                "BAD_REQUEST",
                400,
                "You cannot leave the organization as the only owner",
                Some("YOU_CANNOT_LEAVE_THE_ORGANIZATION_AS_THE_ONLY_OWNER"),
            ),
        };
        let mut body = FieldMap::from([("message".into(), message.into())]);
        if let Some(code) = code {
            let _ = body.insert("code".into(), code.into());
        }
        (name, status, body.into())
    }
}
