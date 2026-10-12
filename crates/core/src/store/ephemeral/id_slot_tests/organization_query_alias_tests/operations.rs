use super::*;
use crate::{UpdateOrganizationRole, UpdateTeam};

fn record_value(record: impl AuthRecordFields) -> AuthResult<Value> {
    Ok(record.field_values()?.into())
}

fn optional_record(record: Option<impl AuthRecordFields>) -> AuthResult<Value> {
    record
        .map(record_value)
        .transpose()
        .map(|value| value.unwrap_or(Value::Null))
}

fn member_user(record: Option<crate::store::MemberUser>) -> AuthResult<Value> {
    let Some(record) = record else {
        return Ok(Value::Null);
    };
    let mut fields = record.member.field_values()?;
    let _ = fields.insert("user".into(), record.user.field_values()?.into());
    Ok(fields.into())
}

async fn find(
    store: &EphemeralStore,
    fields: &OrganizationFields,
    model: &str,
    id: &str,
) -> AuthResult<Value> {
    match model {
        "organization" => match store.get_organization_by_id(id).await? {
            Some(record) => fields
                .organization
                .filter_output_value(record.field_values()?.into()),
            None => Ok(Value::Null),
        },
        "member" => member_user(store.get_member_by_id_with_user(id).await?),
        "invitation" => optional_record(store.get_invitation_by_id(id).await?),
        "team" => match store
            .get_team_details_value(&id.into(), None, false)
            .await?
        {
            Some(details) => record_value(details.into_public_parts(&fields.team)?.0),
            None => Ok(Value::Null),
        },
        "organizationRole" => optional_record(store.get_organization_role(id).await?),
        _ => Err(AuthError::internal("Unknown Organization alias read model")),
    }
}

async fn update(
    store: &EphemeralStore,
    fields: &OrganizationFields,
    model: &str,
    id: &str,
) -> AuthResult<Value> {
    match model {
        "organization" => {
            let record = store
                .update_organization(
                    id,
                    UpdateOrganization {
                        name: Some("accepted".into()),
                        ..Default::default()
                    },
                )
                .await?;
            let mut output = record.field_values()?;
            let metadata = output.get("metadata").cloned().unwrap_or_default();
            // This observer compares the helper response after the production client JSON parser.
            let metadata = if metadata.is_truthy() {
                crate::utils::json::parse_client_json(metadata)?
            } else {
                Value::Undefined
            };
            let _ = output.insert("metadata".into(), metadata);
            fields.organization.filter_output_value(output.into())
        }
        "member" => record_value(store.update_member_role(id, "accepted").await?),
        "invitation" => optional_record(
            store
                .update_invitation_status(id, InvitationStatus::Accepted)
                .await?,
        ),
        "team" => record_value(
            store
                .update_team(
                    id,
                    UpdateTeam {
                        name: Some("accepted".into()),
                        ..Default::default()
                    },
                )
                .await?
                .filter_output_fields(&fields.team)?,
        ),
        "organizationRole" => record_value(
            store
                .update_organization_role(
                    id,
                    UpdateOrganizationRole {
                        role: Some("accepted".into()),
                        ..Default::default()
                    },
                )
                .await?,
        ),
        _ => Err(AuthError::internal(
            "Unknown Organization alias update model",
        )),
    }
}

async fn delete(store: &EphemeralStore, model: &str, id: &str) -> AuthResult<Value> {
    match model {
        "organization" => store.delete_organization(id).await?,
        "member" => store.delete_member_for_user(id, "parent", "owner").await?,
        "team" => store.delete_team(id).await?,
        "organizationRole" => store.delete_organization_role(id).await?,
        "invitation" => {
            // Invitation has no public delete helper on either side; compare the adapter primitive.
            let selector =
                store.organization_query_field(EntityRole::Invitation, "id", id.into())?;
            let _ = store.delete_organization_rows(EntityRole::Invitation, &[selector])?;
        }
        _ => {
            return Err(AuthError::internal(
                "Unknown Organization alias delete model",
            ));
        }
    }
    Ok(Value::Undefined)
}

fn request(model: &str, operation: &str, id: &str) -> AuthResult<JsonValue> {
    let input = match (model, operation) {
        ("organization", "find") => json!(["getOrgAdapter.findOrganizationById", [id]]),
        ("member", "find") => json!(["getOrgAdapter.findMemberById", [id]]),
        ("invitation", "find") => json!(["getOrgAdapter.findInvitationById", [id]]),
        ("team", "find") => json!(["getOrgAdapter.findTeamById", [{"teamId":id}]]),
        ("organization", "update") => {
            json!(["getOrgAdapter.updateOrganization", [id, {"name":"accepted"}]])
        }
        ("member", "update") => json!(["getOrgAdapter.updateMember", [id, "accepted"]]),
        ("invitation", "update") => {
            json!(["getOrgAdapter.updateInvitation", [{"invitationId":id,"status":"accepted"}]])
        }
        ("team", "update") => json!(["getOrgAdapter.updateTeam", [id, {"name":"accepted"}]]),
        ("organization", "delete") => json!(["getOrgAdapter.deleteOrganization", [id]]),
        ("member", "delete") => {
            json!(["getOrgAdapter.deleteMember", [{"memberId":id,"organizationId":"parent","userId":"owner"}]])
        }
        ("team", "delete") => json!(["getOrgAdapter.deleteTeam", [id]]),
        (_, "find") => {
            json!(["adapter.findOne", [{"model":model,"where":[{"field":"id","value":id}]}]])
        }
        (_, "update") => {
            json!(["adapter.update", [{"model":model,"where":[{"field":"id","value":id}],"update":{"role":"accepted"}}]])
        }
        (_, "delete") => {
            json!(["adapter.delete", [{"model":model,"where":[{"field":"id","value":id}]}]])
        }
        _ => return Err(AuthError::internal("Unknown Organization alias request")),
    };
    Ok(input)
}

pub(super) async fn execute(
    store: &EphemeralStore,
    fields: &OrganizationFields,
    case: &JsonValue,
    index: usize,
) -> AuthResult<(JsonValue, Value)> {
    let scenario = required(case["scenario"].as_str())?;
    if scenario.starts_with("member-user-") {
        return Ok((
            json!({"userId":"user-alias","organizationId":"parent"}),
            member_user(store.get_member_with_user("parent", "user-alias").await?)?,
        ));
    }
    if scenario.starts_with("invitation-atomic-")
        || scenario.starts_with("invitation-own-selector-update-")
    {
        return Ok((
            json!({"invitationId":"invitation-alias","status":"accepted"}),
            optional_record(
                store
                    .update_invitation_status_value(
                        &"invitation-alias".into(),
                        InvitationStatus::Accepted,
                    )
                    .await?,
            )?,
        ));
    }
    let model = required(case["model"].as_str())?;
    let operation = if index == 0 {
        required(case["operation"].as_str())?
    } else {
        "find"
    };
    let id = required(case[if index == 1 { "canonical" } else { "alias" }].as_str())?;
    let input = request(model, operation, id)?;
    let result = match operation {
        "find" => find(store, fields, model, id).await?,
        "update" => update(store, fields, model, id).await?,
        "delete" => delete(store, model, id).await?,
        _ => return Err(AuthError::internal("Unknown Organization alias operation")),
    };
    Ok((input, result))
}
