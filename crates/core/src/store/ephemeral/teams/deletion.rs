use super::*;

impl EphemeralStore {
    pub(super) async fn delete_team_with_context(
        &self,
        requested_id: &Value,
        request_organization: Option<&Value>,
    ) -> AuthResult<()> {
        let team_schema = self.field_config(EntityRole::Team)?;
        let membership_schema = self.field_config(EntityRole::TeamMember)?;
        let invitation_schema = self.field_config(EntityRole::Invitation)?;
        let member_team =
            self.organization_query(EntityRole::TeamMember, "teamId", requested_id.clone())?;
        let id = self.organization_query(EntityRole::Team, "id", requested_id.clone())?;
        let (stored_owner, public_id, selectors, rows, snapshot) = {
            let state = self.lock()?;
            let team = state.teams.get(&id)?;
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
            let rows = state
                .invitations
                .select_refs(|row| Self::matches_pending_invitation(row, &selectors))?;
            let snapshot = rows
                .iter()
                .map(|row| row.read(|row| Ok(row.clone())))
                .collect::<AuthResult<Vec<_>>>()?;
            (stored_owner, public_id, selectors, rows, snapshot)
        };
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
            let invitation_id =
                self.organization_query(EntityRole::Invitation, "id", invitation.id.field_value())?;
            let current = self
                .lock()?
                .invitations
                .get(&invitation_id)?
                .ok_or_else(|| AuthError::not_found("Invitation not found"))?;
            let _ = self.output_invitation(patch.clone().apply(current)).await?;
            updates.push((invitation_id, patch));
        }
        let mut state = self.lock()?;
        let team = state.teams.get(&id)?;
        let pending: Vec<_> = state
            .invitations
            .snapshot()?
            .into_iter()
            .filter(|row| Self::matches_pending_invitation(row, &selectors))
            .collect();
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
        let same_owner = match (&stored_owner, &current_owner) {
            (Some(before), Some(current)) => before.strict_equals(current),
            (None, None) => true,
            _ => false,
        };
        if !same_owner || !unchanged {
            return Err(AuthError::conflict(
                "Team invitations changed while field transforms were pending",
            ));
        }
        let updates = updates
            .into_iter()
            .map(|(id, patch)| {
                let row = state
                    .invitations
                    .get(&id)?
                    .ok_or_else(|| AuthError::not_found("Invitation not found"))?;
                Ok((id, patch.apply(row)))
            })
            .collect::<AuthResult<Vec<_>>>()?;
        let _ = state.teams.remove(&id)?;
        state.team_members.retain(|member| {
            !organization_value(member, &membership_schema, "teamId")
                .strict_equals(&member_team.field_value())
        })?;
        for (id, invitation) in updates {
            let _ = state.invitations.replace(&id, invitation)?;
        }
        Ok(())
    }
}
