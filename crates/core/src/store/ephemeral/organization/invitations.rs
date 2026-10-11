use super::*;

#[async_trait]
impl InvitationStore for EphemeralStore {
    async fn create_invitation(&self, mut input: CreateInvitation) -> AuthResult<Invitation> {
        let mut invitation = Invitation {
            field_order: Default::default(),
            additional_fields: Default::default(),
            id: input.id.map(crate::SchemaValue::Typed).unwrap_or_default(),
            organization_id: input.organization_id,
            email: (input.email).into(),
            role: input.role.into(),
            status: (input.status.unwrap_or_default()).into(),
            inviter_id: input.inviter_id,
            team_id: (input.team_id).into(),
            expires_at: (input.expires_at).into(),
            created_at: (input.created_at.unwrap_or_else(|| Utc::now().into())).into(),
        };
        if let Some(value) = input.additional_fields.remove("status") {
            invitation.status = crate::SchemaValue::Dynamic(value);
        }
        if let Some(value) = input.additional_fields.remove("createdAt") {
            invitation.created_at = crate::SchemaValue::Dynamic(value);
        }
        if let Some(value) = input.additional_fields.remove("expiresAt") {
            invitation.expires_at = crate::SchemaValue::Dynamic(value);
        }
        if let Some(value) = input.additional_fields.remove("inviterId") {
            invitation.inviter_id = crate::SchemaValue::Dynamic(value);
        }
        let mut invitation = self
            .create_record(EntityRole::Invitation, invitation, input.additional_fields)
            .await?;
        let source = {
            let mut state = self.lock()?;
            if let Some(id) = self.next_serial_id(state.invitations.len()) {
                let _ = invitation.insert("id".into(), id);
            }
            state.invitations.push_ref(invitation)
        };
        Ok(self
            .output_record_refs(EntityRole::Invitation, vec![source])
            .await?
            .remove(0))
    }
    async fn get_invitation_by_id(&self, id: &str) -> AuthResult<Option<Invitation>> {
        self.get_invitation_by_id_value(&id.into()).await
    }
    async fn get_invitation_by_id_value(&self, id: &Value) -> AuthResult<Option<Invitation>> {
        let id = self
            .organization_query(EntityRole::Invitation, "id", id.clone())?
            .field_value();
        let row = self.lock()?.invitations.first_ref(|row| {
            crate::query::field_matches_equality(row.get("id").unwrap_or(&Value::Undefined), &id)
        })?;
        match row {
            Some(row) => Ok(self
                .output_record_refs(EntityRole::Invitation, vec![row])
                .await?
                .pop()),
            None => Ok(None),
        }
    }
    async fn get_pending_invitation(
        &self,
        org: &str,
        email: &str,
    ) -> AuthResult<Option<Invitation>> {
        self.get_pending_invitation_value(&org.into(), email).await
    }
    async fn get_pending_invitation_value(
        &self,
        org: &Value,
        email: &str,
    ) -> AuthResult<Option<Invitation>> {
        Ok(self
            .pending_invitation_rows(org, Some(email))
            .await?
            .into_iter()
            .next())
    }
    async fn update_invitation_status(
        &self,
        id: &str,
        status: InvitationStatus,
    ) -> AuthResult<Option<Invitation>> {
        self.update_invitation_status_value(&id.into(), status)
            .await
    }
    async fn update_invitation_status_value(
        &self,
        id: &Value,
        status: InvitationStatus,
    ) -> AuthResult<Option<Invitation>> {
        let id = self
            .organization_query(EntityRole::Invitation, "id", id.clone())?
            .field_value();
        let patch = self
            .prepare_record_patch(
                EntityRole::Invitation,
                [("status".into(), status.into_field())]
                    .into_iter()
                    .collect(),
                FieldMap::new(),
            )
            .await?;
        let source = {
            let state = self.lock()?;
            let selected = state.invitations.select_refs(|row| {
                crate::query::field_matches_equality(
                    row.get("id").unwrap_or(&Value::Undefined),
                    &id,
                )
            })?;
            for source in &selected {
                source.write(|row| {
                    patch.clone().apply_to(row);
                    Ok(())
                })?;
            }
            selected.into_iter().next()
        };
        match source {
            Some(source) => Ok(self
                .output_record_refs(EntityRole::Invitation, vec![source])
                .await?
                .pop()),
            None => Ok(None),
        }
    }
    async fn update_invitation_expiry(
        &self,
        id: &str,
        expires_at: DateTime<Utc>,
    ) -> AuthResult<Invitation> {
        self.update_invitation_expiry_value(&id.into(), expires_at)
            .await
    }
    async fn update_invitation_expiry_value(
        &self,
        id: &Value,
        expires_at: DateTime<Utc>,
    ) -> AuthResult<Invitation> {
        let id = self
            .organization_query(EntityRole::Invitation, "id", id.clone())?
            .field_value();
        let patch = self
            .prepare_record_patch(
                EntityRole::Invitation,
                [("expiresAt".into(), Value::from(expires_at))]
                    .into_iter()
                    .collect(),
                FieldMap::new(),
            )
            .await?;
        let source = {
            let state = self.lock()?;
            let selected = state.invitations.select_refs(|row| {
                crate::query::field_matches_equality(
                    row.get("id").unwrap_or(&Value::Undefined),
                    &id,
                )
            })?;
            for source in &selected {
                source.write(|row| {
                    patch.clone().apply_to(row);
                    Ok(())
                })?;
            }
            selected.into_iter().next()
        }
        .ok_or_else(|| AuthError::not_found("Invitation not found"))?;
        Ok(self
            .output_record_refs(EntityRole::Invitation, vec![source])
            .await?
            .remove(0))
    }
    async fn list_organization_invitations(&self, org: &str) -> AuthResult<Vec<Invitation>> {
        self.list_organization_invitations_value(&Value::from(org))
            .await
    }
    async fn list_organization_invitations_value(
        &self,
        org: &Value,
    ) -> AuthResult<Vec<Invitation>> {
        let org = self.organization_query(EntityRole::Invitation, "organizationId", org.clone())?;
        let schema = self.field_config(EntityRole::Invitation)?;
        let rows = self.lock()?.invitations.select_refs(|row| {
            organization_value(row, &schema, "organizationId").strict_equals(&org.field_value())
        })?;
        let rows = crate::query::paginate_memory(
            rows,
            Some(self.config.advanced.database.find_many_limit()),
            None,
        );
        self.output_record_refs(EntityRole::Invitation, rows).await
    }
    async fn count_pending_organization_invitations(&self, org: &str) -> AuthResult<i64> {
        self.count_pending_organization_invitations_value(&org.into())
            .await
    }
    async fn count_pending_organization_invitations_value(&self, org: &Value) -> AuthResult<i64> {
        Ok(self.pending_invitation_rows(org, None).await?.len() as i64)
    }
    async fn list_user_invitations(
        &self,
        email: &str,
    ) -> AuthResult<Vec<crate::store::InvitationOrganization>> {
        self.joined_user_invitations(email).await
    }
}

impl EphemeralStore {
    pub(in crate::store::ephemeral) fn pending_invitation_selectors(
        &self,
        organization_id: &Value,
        email: Option<&str>,
    ) -> AuthResult<Vec<(String, Value)>> {
        let mut selectors = Vec::new();
        if let Some(email) = email {
            selectors.push(("email", Value::from(email.to_lowercase())));
        }
        selectors.extend([
            ("organizationId", organization_id.clone()),
            ("status", "pending".into()),
        ]);
        let schema = self.field_config(EntityRole::Invitation)?;
        selectors
            .into_iter()
            .map(|(name, value)| {
                let value = self
                    .organization_query(EntityRole::Invitation, name, value)?
                    .field_value();
                Ok((schema.record_storage_key(name).to_owned(), value))
            })
            .collect()
    }

    pub(in crate::store::ephemeral) fn matches_pending_invitation(
        row: &FieldMap,
        selectors: &[(String, Value)],
    ) -> bool {
        selectors.iter().all(|(name, value)| {
            crate::query::field_matches_equality(row.get(name).unwrap_or(&Value::Undefined), value)
        })
    }

    async fn pending_invitation_rows(
        &self,
        organization_id: &Value,
        email: Option<&str>,
    ) -> AuthResult<Vec<Invitation>> {
        let selectors = self.pending_invitation_selectors(organization_id, email)?;
        let rows = self
            .lock()?
            .invitations
            .select_refs(|row| Self::matches_pending_invitation(row, &selectors))?;
        self.project_pending_invitation_rows(rows).await
    }

    pub(in crate::store::ephemeral) async fn project_pending_invitation_rows(
        &self,
        rows: Vec<super::super::rows::RowRef<FieldMap>>,
    ) -> AuthResult<Vec<Invitation>> {
        let rows = crate::query::paginate_memory(
            rows,
            Some(self.config.advanced.database.find_many_limit()),
            None,
        );
        let rows = self
            .output_record_refs::<Invitation>(EntityRole::Invitation, rows)
            .await?;
        rows.into_iter()
            .try_fold(Vec::new(), |mut live, invitation| {
                if invitation
                    .expires_at
                    .clone()
                    .converted_date()?
                    .is_after(Utc::now())?
                {
                    live.push(invitation);
                }
                Ok(live)
            })
    }
}
