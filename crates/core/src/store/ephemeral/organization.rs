use super::*;
use better_auth_schema_registry::EntityRole;

mod invitations;
#[cfg(test)]
mod member_query_schedule_tests;
mod members;
#[cfg(test)]
mod query_tests;

#[async_trait]
impl OrganizationStore for EphemeralStore {
    async fn get_organization_details(
        &self,
        query: crate::store::OrganizationDetailsQuery<'_>,
    ) -> AuthResult<Option<crate::store::OrganizationDetails>> {
        self.read_organization_details(query).await
    }

    async fn insert_organization(&self, mut record: Organization) -> AuthResult<Organization> {
        let fields = std::mem::take(&mut record.additional_fields);
        let record = self
            .create_record(EntityRole::Organization, record, fields)
            .await?;
        let source = self.insert_organization_row(EntityRole::Organization, record)?;
        Ok(self
            .output_record_refs(EntityRole::Organization, vec![source])
            .await?
            .remove(0))
    }
    async fn delete_organization_records(&self, id: &str) -> AuthResult<()> {
        let member_org =
            self.organization_query_field(EntityRole::Member, "organizationId", Value::from(id))?;
        let _ = self.delete_organization_rows(EntityRole::Member, &[member_org])?;
        let invitation_org = self.organization_query_field(
            EntityRole::Invitation,
            "organizationId",
            Value::from(id),
        )?;
        let _ = self.delete_organization_rows(EntityRole::Invitation, &[invitation_org])?;
        let id = self.organization_query_field(EntityRole::Organization, "id", Value::from(id))?;
        let _ = self.delete_organization_rows(EntityRole::Organization, &[id])?;
        Ok(())
    }

    fn configure_organization_fields(
        &self,
        fields: crate::organization_fields::OrganizationFields,
    ) -> AuthResult<()> {
        let fields = fields.into_storage();
        *self
            .organization_fields
            .write()
            .map_err(|_| AuthError::internal("Ephemeral organization schema lock poisoned"))? =
            fields;
        Ok(())
    }
    async fn create_organization(&self, input: CreateOrganization) -> AuthResult<Organization> {
        let slug = self.organization_query_field(
            EntityRole::Organization,
            "slug",
            input.slug.field_value(),
        )?;
        let selector = [slug];
        if !self
            .select_organization_rows(EntityRole::Organization, &selector)?
            .is_empty()
        {
            return Err(AuthError::bad_request("Organization already exists"));
        }
        let metadata = crate::organization_fields::metadata_input(
            (!input.metadata.is_undefined()).then(|| input.metadata.field_value()),
            true,
        )?
        .map(crate::SchemaValue::from_field)
        .unwrap_or_default();
        let org = Organization {
            field_order: Default::default(),
            additional_fields: Default::default(),
            id: input.id.map(crate::SchemaValue::Typed).unwrap_or_default(),
            name: input.name,
            slug: input.slug,
            logo: input.logo,
            metadata,
            created_at: (Utc::now()).into(),
        };
        let org = self
            .create_record(EntityRole::Organization, org, input.additional_fields)
            .await?;
        let source = self.operation(|op| {
            if !op
                .capture_table(EntityRole::Organization)?
                .select_refs(|row| super::organization_rows::matches(row, &selector))?
                .is_empty()
            {
                return Err(AuthError::bad_request("Organization already exists"));
            }
            self.insert_organization_row(EntityRole::Organization, org)
        })?;
        Ok(self
            .output_record_refs(EntityRole::Organization, vec![source])
            .await?
            .remove(0))
    }
    async fn get_organization_by_id(&self, id: &str) -> AuthResult<Option<Organization>> {
        self.get_organization_by_id_value(&Value::from(id)).await
    }
    async fn get_organization_by_id_value(&self, id: &Value) -> AuthResult<Option<Organization>> {
        let id = self.organization_query_field(EntityRole::Organization, "id", id.clone())?;
        let row = self
            .select_organization_rows(EntityRole::Organization, &[id])?
            .into_iter()
            .next();
        match row {
            Some(row) => Ok(self
                .output_record_refs(EntityRole::Organization, vec![row])
                .await?
                .pop()),
            None => Ok(None),
        }
    }
    async fn get_organization_by_slug(&self, slug: &str) -> AuthResult<Option<Organization>> {
        self.get_organization_by_slug_value(&Value::from(slug))
            .await
    }
    async fn get_organization_by_slug_value(
        &self,
        slug: &Value,
    ) -> AuthResult<Option<Organization>> {
        let slug = self.organization_query_field(EntityRole::Organization, "slug", slug.clone())?;
        let row = self
            .select_organization_rows(EntityRole::Organization, &[slug])?
            .into_iter()
            .next();
        match row {
            Some(row) => Ok(self
                .output_record_refs(EntityRole::Organization, vec![row])
                .await?
                .pop()),
            None => Ok(None),
        }
    }
    async fn list_organizations_by_ids(&self, ids: &[String]) -> AuthResult<Vec<Organization>> {
        let (column, ids) = self.organization_query_field(
            EntityRole::Organization,
            "id",
            ids.iter()
                .map(|id| Value::from(id.as_str()))
                .collect::<Vec<_>>()
                .into(),
        )?;
        let rows = self.operation(|op| {
            op.capture_table(EntityRole::Organization)?
                .select_refs(|row| {
                    crate::memory_query::matches(
                        row.field(&column)?.as_ref(),
                        &ids,
                        crate::WhereOperator::In,
                        crate::WhereMode::Sensitive,
                    )
                })
        })?;
        self.output_record_refs(EntityRole::Organization, rows)
            .await
    }
    async fn update_organization(
        &self,
        id: &str,
        update: UpdateOrganization,
    ) -> AuthResult<Organization> {
        self.update_organization_value(&Value::from(id), update)
            .await
    }
    async fn update_organization_value(
        &self,
        id: &Value,
        update: UpdateOrganization,
    ) -> AuthResult<Organization> {
        let id = self.organization_query_field(EntityRole::Organization, "id", id.clone())?;
        let mut patch = FieldMap::new();
        if let Some(name) = update.name {
            let _ = patch.insert("name".into(), Value::from(name));
        }
        if let Some(slug) = update.slug {
            let _ = patch.insert("slug".into(), Value::from(slug));
        }
        if let Some(logo) = update.logo {
            let _ = patch.insert("logo".into(), logo.into_field());
        }
        if let Some(created_at) = update.created_at {
            let _ = patch.insert("createdAt".into(), Value::from(created_at));
        }
        if let Some(new_id) = update.id {
            let _ = patch.insert("id".into(), Value::from(new_id));
        }
        if let Some(value) = crate::organization_fields::metadata_input(update.metadata, false)? {
            let _ = patch.insert("metadata".into(), value);
        }
        let patch = self
            .prepare_record_patch(EntityRole::Organization, patch, update.additional_fields)
            .await?;
        let source = self
            .patch_organization_rows(
                EntityRole::Organization,
                &[id],
                patch.apply(FieldMap::new()),
                false,
            )?
            .ok_or_else(|| AuthError::not_found("Organization not found"))?;
        Ok(self
            .output_record_refs(EntityRole::Organization, vec![source])
            .await?
            .remove(0))
    }
    async fn delete_organization(&self, id: &str) -> AuthResult<()> {
        if self.pending_hooks.is_some() {
            return self.delete_organization_records(id).await;
        }
        let (base, isolated, pending_hooks) = self.begin_adapter_transaction()?;
        isolated.delete_organization_records(id).await?;
        self.commit_transaction(base, isolated, pending_hooks).await
    }
    async fn list_user_organizations(
        &self,
        user_id: &str,
    ) -> AuthResult<Vec<crate::store::JoinValue<FieldMap>>> {
        self.list_user_organizations_value(&user_id.into()).await
    }

    async fn list_user_organizations_value(
        &self,
        user_id: &Value,
    ) -> AuthResult<Vec<crate::store::JoinValue<FieldMap>>> {
        self.joined_user_organizations(user_id).await
    }
}
