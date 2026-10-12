use super::types::OrganizationResponse;
use better_auth_core::{
    AuthContext, AuthResult, AuthSchema, FieldValue, FromFieldMap, Team, entity::AuthOrganization,
};

pub(super) fn invitation_team_id_is_declared(config: &super::OrganizationConfig) -> bool {
    config.teams.enabled || config.schema.invitation.fields().contains_key("teamId")
}

pub(super) fn invitation_snapshot(
    mut invitation: better_auth_core::Invitation,
    config: &super::OrganizationConfig,
) -> better_auth_core::Invitation {
    if !invitation_team_id_is_declared(config) {
        invitation.team_id = better_auth_core::SchemaValue::Undefined;
    }
    invitation
}

pub(super) fn organization(
    organization: &impl AuthOrganization,
    ctx: &AuthContext<impl AuthSchema>,
) -> AuthResult<OrganizationResponse> {
    let fields =
        organization_value(organization.field_values()?.into(), ctx)?.enumerable_fields()?;
    OrganizationResponse::from_field_values(fields)
}

pub(super) fn organization_value(
    value: FieldValue,
    ctx: &AuthContext<impl AuthSchema>,
) -> AuthResult<FieldValue> {
    match ctx.extensions.get::<super::OrganizationPlugin>() {
        Some(plugin) => plugin.config.schema.organization.filter_output_value(value),
        None => Ok(value),
    }
}

pub(super) fn team(
    team: Team,
    config: &super::OrganizationConfig,
) -> better_auth_core::AuthResult<Team> {
    team.filter_output_fields(&config.schema.team)
}
