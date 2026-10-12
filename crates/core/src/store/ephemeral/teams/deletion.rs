use super::*;

impl EphemeralStore {
    pub(super) async fn delete_team_with_context(
        &self,
        requested_id: &Value,
        request_organization: Option<&Value>,
    ) -> AuthResult<()> {
        let team_schema = self.field_config(EntityRole::Team)?;
        let invitation_schema = self.field_config(EntityRole::Invitation)?;
        let member_team =
            self.organization_query_field(EntityRole::TeamMember, "teamId", requested_id.clone())?;
        let id = self.organization_query_field(EntityRole::Team, "id", requested_id.clone())?;
        let (selected_team, stored_owner, public_id, selectors, rows, snapshot) =
            self.operation(|op| {
                let state = op.capture_state()?;
                let selected_team = super::super::organization_rows::select_one(
                    self.snapshot_table(&state, EntityRole::Team)?,
                    std::slice::from_ref(&id),
                )?;
                let team = selected_team
                    .as_ref()
                    .map(|row| row.shallow_fields())
                    .transpose()?;
                // The stored owner guards concurrent changes independently of the caller's invitation scope.
                let stored_owner = team
                    .as_ref()
                    .map(|team| organization_value(team, &team_schema, "organizationId"));
                let (organization_id, public_id) = match (request_organization, team.as_ref()) {
                    (Some(organization_id), _) => (organization_id.clone(), requested_id.clone()),
                    (None, Some(team)) => (
                        organization_value(team, &team_schema, "organizationId"),
                        Self::project_id(&super::super::organization_rows::id(team))?.field_value(),
                    ),
                    (None, None) => return Err(AuthError::not_found("Team not found")),
                };
                let selectors = self.pending_invitation_selectors(&organization_id, None)?;
                let rows = op
                    .capture_table(EntityRole::Invitation)?
                    .select_refs(|row| Self::matches_pending_invitation(row, &selectors))?;
                let snapshot = rows
                    .iter()
                    .map(|row| row.shallow_fields())
                    .collect::<AuthResult<Vec<_>>>()?;
                Ok((
                    selected_team,
                    stored_owner,
                    public_id,
                    selectors,
                    rows,
                    snapshot,
                ))
            })?;
        let pending = self.project_pending_invitation_rows(rows).await?;
        let mut updates = Vec::new();
        for invitation in pending {
            let Some(ids) = invitation.team_id.typed()?.as_ref() else {
                continue;
            };
            let retained: Vec<_> = ids
                .split(',')
                .filter(|team_id| !Value::from(*team_id).strict_equals(&public_id))
                .collect();
            if retained.len() == ids.split(',').count() {
                continue;
            }
            let patch = self
                .prepare_record_patch(
                    EntityRole::Invitation,
                    [(
                        "teamId".into(),
                        (!retained.is_empty())
                            .then(|| retained.join(","))
                            .into_field(),
                    )]
                    .into_iter()
                    .collect(),
                    FieldMap::new(),
                )
                .await?;
            let invitation_id = self.organization_query_field(
                EntityRole::Invitation,
                "id",
                invitation.id.field_value(),
            )?;
            let current = self
                .operation(|op| {
                    super::super::organization_rows::select_one(
                        &op.capture_table(EntityRole::Invitation)?,
                        std::slice::from_ref(&invitation_id),
                    )
                })?
                .ok_or_else(|| AuthError::not_found("Invitation not found"))?;
            let _ = self
                .output_invitation(patch.clone().apply(current.shallow_fields()?))
                .await?;
            updates.push((invitation_id, current, patch));
        }
        self.operation(|op| {
            let state = op.shallow_snapshot()?;
            let current_team = super::super::organization_rows::select_one(
                self.snapshot_table(&state, EntityRole::Team)?,
                std::slice::from_ref(&id),
            )?;
            let team = current_team
                .as_ref()
                .map(|row| row.shallow_fields())
                .transpose()?;
            let pending = self
                .snapshot_table(&state, EntityRole::Invitation)?
                .select_refs(|row| Self::matches_pending_invitation(row, &selectors))?
                .iter()
                .map(|row| row.shallow_fields())
                .collect::<AuthResult<Vec<_>>>()?;
            let unchanged = pending.len() == snapshot.len()
                && pending.iter().zip(&snapshot).all(|(a, b)| {
                    super::super::organization_rows::id(a) == super::super::organization_rows::id(b)
                        && ["teamId", "expiresAt"].iter().all(|name| {
                            organization_value(a, &invitation_schema, name)
                                == organization_value(b, &invitation_schema, name)
                        })
                });
            let current_owner = team
                .as_ref()
                .map(|team| organization_value(team, &team_schema, "organizationId"));
            let same_team = match (&selected_team, &current_team) {
                (Some(before), Some(current)) => before.same_row(current),
                (None, None) => true,
                _ => false,
            };
            let same_owner = match (&stored_owner, &current_owner) {
                (Some(before), Some(current)) => before.strict_equals(current),
                (None, None) => true,
                _ => false,
            };
            if !same_team || !same_owner || !unchanged {
                return Err(AuthError::conflict(
                    "Team invitations changed while field transforms were pending",
                ));
            }
            let updates = updates
                .into_iter()
                .map(|(id, selected, patch)| {
                    let row = super::super::organization_rows::select_one(
                        self.snapshot_table(&state, EntityRole::Invitation)?,
                        std::slice::from_ref(&id),
                    )?
                    .ok_or_else(|| AuthError::not_found("Invitation not found"))?;
                    if !selected.same_row(&row) {
                        return Err(AuthError::conflict(
                            "Team invitations changed while field transforms were pending",
                        ));
                    }
                    let fields = patch.apply(row.shallow_fields()?);
                    Ok((row, fields))
                })
                .collect::<AuthResult<Vec<_>>>()?;
            let teams = self
                .snapshot_table(&state, EntityRole::Team)?
                .without_refs(&current_team.into_iter().collect::<Vec<_>>())?;
            let removed = self
                .snapshot_table(&state, EntityRole::TeamMember)?
                .select_refs(|row| {
                    super::super::organization_rows::matches(
                        row,
                        std::slice::from_ref(&member_team),
                    )
                })?;
            let memberships = self
                .snapshot_table(&state, EntityRole::TeamMember)?
                .without_refs(&removed)?;
            for (row, invitation) in updates {
                row.replace(invitation)?;
            }
            op.replace_table(EntityRole::Team, teams)?;
            op.replace_table(EntityRole::TeamMember, memberships)
        })
    }
}
