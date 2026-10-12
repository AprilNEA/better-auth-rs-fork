use super::*;

mod query;

#[async_trait]
impl MemberStore for EphemeralStore {
    async fn get_member_with_user(
        &self,
        organization_id: &str,
        user_id: &str,
    ) -> AuthResult<Option<crate::store::MemberUser>> {
        let organization_id = self.organization_query(
            EntityRole::Member,
            "organizationId",
            Value::from(organization_id),
        )?;
        let user_id =
            self.organization_query(EntityRole::Member, "userId", Value::from(user_id))?;
        self.read_member_user(
            |row| {
                Ok(row
                    .organization_id
                    .field_value()
                    .strict_equals(&organization_id.field_value())
                    && row
                        .user_id
                        .field_value()
                        .strict_equals(&user_id.field_value()))
            },
            false,
        )
        .await
    }
    async fn get_member_with_user_value(
        &self,
        organization_id: &Value,
        user_id: &Value,
    ) -> AuthResult<Option<crate::store::MemberUser>> {
        let organization_id = self.organization_query(
            EntityRole::Member,
            "organizationId",
            organization_id.clone(),
        )?;
        let user_id = self.organization_query(EntityRole::Member, "userId", user_id.clone())?;
        self.read_member_user(
            |row| {
                Ok(row
                    .organization_id
                    .field_value()
                    .strict_equals(&organization_id.field_value())
                    && row
                        .user_id
                        .field_value()
                        .strict_equals(&user_id.field_value()))
            },
            false,
        )
        .await
    }
    async fn get_member_by_id_with_user(
        &self,
        id: &str,
    ) -> AuthResult<Option<crate::store::MemberUser>> {
        let id = self.organization_query(EntityRole::Member, "id", Value::from(id))?;
        self.read_member_user(|row| Ok(row.id == id), true).await
    }

    async fn insert_member(&self, mut record: Member) -> AuthResult<Member> {
        let fields = std::mem::take(&mut record.additional_fields);
        let record = self
            .create_record(EntityRole::Member, record, fields)
            .await?;
        let source = self
            .raw("member", "create", |_| {
                self.insert_organization_row(EntityRole::Member, record)
            })
            .await?;
        Ok(self
            .output_record_refs(EntityRole::Member, vec![source])
            .await?
            .remove(0))
    }

    async fn create_member(&self, input: CreateMember) -> AuthResult<Member> {
        let member = Member {
            field_order: Default::default(),
            additional_fields: Default::default(),
            id: Default::default(),
            organization_id: input.organization_id,
            user_id: input.user_id,
            role: input.role,
            created_at: (Utc::now()).into(),
        };
        let member = self
            .create_record(EntityRole::Member, member, input.additional_fields)
            .await?;
        let source = self
            .raw("member", "create", |_| {
                self.insert_organization_row(EntityRole::Member, member)
            })
            .await?;
        Ok(self
            .output_record_refs(EntityRole::Member, vec![source])
            .await?
            .remove(0))
    }
    async fn get_member(&self, organization_id: &str, user_id: &str) -> AuthResult<Option<Member>> {
        self.get_member_value(&organization_id.into(), &user_id.into())
            .await
    }
    async fn get_member_value(
        &self,
        organization_id: &Value,
        user_id: &Value,
    ) -> AuthResult<Option<Member>> {
        let organization_id = self.organization_query(
            EntityRole::Member,
            "organizationId",
            organization_id.clone(),
        )?;
        let user_id = self.organization_query(EntityRole::Member, "userId", user_id.clone())?;
        let schema = self.field_config(EntityRole::Member)?;
        let selected = self
            .raw("member", "findOne", |_| {
                Ok(self
                    .select_organization_rows(
                        EntityRole::Member,
                        &[
                            (
                                schema.record_storage_key("organizationId").into(),
                                organization_id.field_value(),
                            ),
                            (
                                schema.record_storage_key("userId").into(),
                                user_id.field_value(),
                            ),
                        ],
                    )?
                    .into_iter()
                    .next())
            })
            .await?;
        Ok(self
            .output_record_refs::<Member>(EntityRole::Member, selected.into_iter().collect())
            .await?
            .pop())
    }
    async fn get_member_by_id(&self, id: &str) -> AuthResult<Option<Member>> {
        let id = self.organization_query(EntityRole::Member, "id", Value::from(id))?;
        let selected = self
            .raw("member", "findOne", |_| {
                Ok(self
                    .select_organization_rows(
                        EntityRole::Member,
                        &[("id".into(), id.field_value())],
                    )?
                    .into_iter()
                    .next())
            })
            .await?;
        Ok(self
            .output_record_refs::<Member>(EntityRole::Member, selected.into_iter().collect())
            .await?
            .pop())
    }
    async fn update_member_role(&self, id: &str, role: &str) -> AuthResult<Member> {
        self.update_member_role_value(&id.into(), role).await
    }
    async fn update_member_role_value(&self, id: &Value, role: &str) -> AuthResult<Member> {
        self.update_member_role_optional_value(id, role)
            .await?
            .ok_or_else(|| AuthError::not_found("Member not found"))
    }
    async fn update_member_role_optional_value(
        &self,
        id: &Value,
        role: &str,
    ) -> AuthResult<Option<Member>> {
        let id = self.organization_query(EntityRole::Member, "id", id.clone())?;
        let patch = self
            .prepare_record_patch(
                EntityRole::Member,
                [("role".into(), Value::from(role))].into_iter().collect(),
                FieldMap::new(),
            )
            .await?;
        let Some(source) = self
            .raw("member", "update", |_| {
                self.patch_organization_rows(
                    EntityRole::Member,
                    &[("id".into(), id.field_value())],
                    patch.apply(FieldMap::new()),
                    false,
                )
            })
            .await?
        else {
            return Ok(None);
        };
        Ok(Some(
            self.output_record_refs(EntityRole::Member, vec![source])
                .await?
                .remove(0),
        ))
    }
    async fn delete_member(&self, id: &str) -> AuthResult<()> {
        self.delete_member_value(&id.into()).await
    }
    async fn delete_member_value(&self, id: &Value) -> AuthResult<()> {
        let id = id.clone();
        crate::store::transaction(self, move |tx| {
            Box::pin(async move { tx.delete_member_value(&id).await })
        })
        .await
    }
    async fn delete_member_for_user(
        &self,
        id: &str,
        organization_id: &str,
        user_id: &str,
    ) -> AuthResult<()> {
        self.delete_member_for_user_value(&id.into(), &organization_id.into(), &user_id.into())
            .await
    }
    async fn delete_member_for_user_value(
        &self,
        id: &Value,
        organization_id: &Value,
        user_id: &Value,
    ) -> AuthResult<()> {
        let (id, organization_id, user_id) = (id.clone(), organization_id.clone(), user_id.clone());
        crate::store::transaction(self, move |tx| {
            Box::pin(async move {
                tx.delete_member_for_user_value(&id, &organization_id, &user_id)
                    .await
            })
        })
        .await
    }
    async fn list_organization_members(&self, org: &str) -> AuthResult<Vec<Member>> {
        self.list_organization_members_value(&Value::from(org))
            .await
    }
    async fn list_organization_members_value(&self, org: &Value) -> AuthResult<Vec<Member>> {
        let org = self.organization_query(EntityRole::Member, "organizationId", org.clone())?;
        let schema = self.field_config(EntityRole::Member)?;
        let rows = self
            .raw("member", "findMany", |_| {
                self.select_organization_rows(
                    EntityRole::Member,
                    &[(
                        schema.record_storage_key("organizationId").into(),
                        org.field_value(),
                    )],
                )
            })
            .await?;
        self.output_record_refs(EntityRole::Member, rows).await
    }
    async fn query_organization_members(
        &self,
        params: &ListOrganizationMembersParams,
    ) -> AuthResult<(Vec<Member>, usize)> {
        let page_store = self.clone();
        let page_params = params.clone();
        let count_store = self.clone();
        let count_params = params.clone();
        crate::request_runtime::concurrent::pair(
            "Member query task",
            async move { page_store.member_query_page(&page_params).await },
            async move { count_store.member_query_count(&count_params).await },
        )
        .await
    }
    async fn count_organization_members(&self, org: &str) -> AuthResult<i64> {
        let schema = self.field_config(EntityRole::Member)?;
        let org =
            self.organization_query(EntityRole::Member, "organizationId", Value::from(org))?;
        Ok(self
            .select_organization_rows(
                EntityRole::Member,
                &[(
                    schema.record_storage_key("organizationId").into(),
                    org.field_value(),
                )],
            )?
            .len() as i64)
    }

    async fn count_organization_members_value(&self, org: &Value) -> AuthResult<i64> {
        let schema = self.field_config(EntityRole::Member)?;
        let org = self.organization_query(EntityRole::Member, "organizationId", org.clone())?;
        Ok(self
            .select_organization_rows(
                EntityRole::Member,
                &[(
                    schema.record_storage_key("organizationId").into(),
                    org.field_value(),
                )],
            )?
            .len() as i64)
    }

    async fn count_organization_owners(&self, org: &str) -> AuthResult<i64> {
        let schema = self.field_config(EntityRole::Member)?;
        let org =
            self.organization_query(EntityRole::Member, "organizationId", Value::from(org))?;
        self.operation(|_| {
            self.select_organization_rows(
                EntityRole::Member,
                &[(
                    schema.record_storage_key("organizationId").into(),
                    org.field_value(),
                )],
            )?
            .iter()
            .try_fold(0, |count, member| {
                let role = crate::SchemaValue::<String>::from_field(
                    super::super::organization_rows::field(member, &schema, "role")?,
                );
                Ok(count + i64::from(role.typed()?.split(',').any(|role| role == "owner")))
            })
        })
    }
}
