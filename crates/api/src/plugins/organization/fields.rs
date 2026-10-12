use super::types::OrganizationResponse;
use better_auth_core::{
    AuthContext, AuthResult, AuthSchema, FieldValue, FromFieldMap, Team, entity::AuthOrganization,
    organization_fields::OrganizationFields,
};
use serde_json::Value;

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

enum ResponseFields {
    Organization,
    Team,
    Other,
}

fn response_fields(path: &str) -> ResponseFields {
    match path {
        "/organization/delete" | "/organization/get-organization" | "/organization/set-active" => {
            ResponseFields::Organization
        }
        "/organization/create-team"
        | "/organization/update-team"
        | "/organization/list-teams"
        | "/organization/list-user-teams"
        | "/organization/set-active-team" => ResponseFields::Team,
        _ => ResponseFields::Other,
    }
}

pub(super) fn filter_native_response(
    path: &str,
    value: &mut better_auth_core::FieldValue,
    fields: &OrganizationFields,
) -> better_auth_core::AuthResult<()> {
    use better_auth_core::FieldValue;
    fn filter(
        value: &mut FieldValue,
        schema: &better_auth_core::user_fields::UserConfig,
        team: bool,
    ) -> better_auth_core::AuthResult<()> {
        match value {
            FieldValue::Object(object) => {
                let mut fields = object.snapshot_fields()?;
                fields.retain(|name, _| {
                    !(team && name == "memberCount")
                        && schema
                            .fields()
                            .get(name)
                            .is_none_or(|field| field.returned())
                });
                *object = fields.into();
            }
            FieldValue::Array(values) => {
                *values = values
                    .iter()?
                    .map(|value| {
                        let mut value = value?;
                        filter(&mut value, schema, team)?;
                        Ok(value)
                    })
                    .collect::<AuthResult<Vec<_>>>()?
                    .into();
            }
            _ => {}
        }
        Ok(())
    }
    match response_fields(path) {
        ResponseFields::Organization => filter(value, &fields.organization, false)?,
        ResponseFields::Team => filter(value, &fields.team, true)?,
        ResponseFields::Other => {}
    }
    Ok(())
}

pub(super) fn filter_response(path: &str, value: &mut Value, fields: &OrganizationFields) {
    fn filter(value: &mut Value, schema: &better_auth_core::user_fields::UserConfig) {
        match value {
            Value::Object(map) => map.retain(|name, _| {
                schema
                    .fields()
                    .get(name)
                    .is_none_or(|field| field.returned())
            }),
            Value::Array(items) => {
                for item in items {
                    filter(item, schema);
                }
            }
            _ => {}
        }
    }
    match response_fields(path) {
        ResponseFields::Organization => filter(value, &fields.organization),
        ResponseFields::Team => {
            match value {
                Value::Object(team) => {
                    let _ = team.remove("memberCount");
                }
                Value::Array(teams) => {
                    for team in teams {
                        if let Some(team) = team.as_object_mut() {
                            let _ = team.remove("memberCount");
                        }
                    }
                }
                _ => {}
            }
            filter(value, &fields.team);
        }
        ResponseFields::Other => {}
    }
}
