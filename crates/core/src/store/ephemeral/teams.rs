use super::rows::RecordSource;
use super::*;
use crate::{
    CreateOrganizationRole, CreateTeam, OrganizationRole, Team, TeamMember, UpdateOrganizationRole,
    UpdateTeam,
    store::{OrganizationRoleStore, TeamStore},
};
use better_auth_schema_registry::EntityRole;

mod deletion;

#[async_trait]
impl TeamStore for EphemeralStore {
    async fn get_team_details_value(
        &self,
        team_id: &Value,
        organization_id: Option<&Value>,
        include_members: bool,
    ) -> AuthResult<Option<crate::store::TeamDetails>> {
        self.read_team_details(team_id, organization_id, include_members, &[])
            .await
    }
    async fn create_team(&self, mut input: CreateTeam) -> AuthResult<Team> {
        let team = Team {
            field_order: Default::default(),
            additional_fields: [("memberCount".into(), Value::Number(0.0))]
                .into_iter()
                .collect(),
            id: input.id.map(crate::SchemaValue::Typed).unwrap_or_default(),
            name: input.name,
            organization_id: input.organization_id,
            created_at: input
                .additional_fields
                .remove("createdAt")
                .map(crate::SchemaValue::from_field)
                .unwrap_or_else(|| input.created_at.unwrap_or_else(|| Utc::now().into()).into()),
            updated_at: input
                .additional_fields
                .remove("updatedAt")
                .map(crate::SchemaValue::from_field)
                .unwrap_or_else(|| {
                    input
                        .updated_at
                        .map(|value| Some(value).into())
                        .unwrap_or_default()
                }),
        };
        let team = self
            .create_record(EntityRole::Team, team, input.additional_fields)
            .await?;
        let source = self.insert_organization_row(EntityRole::Team, team)?;
        Ok(self
            .output_record_refs(EntityRole::Team, vec![source])
            .await?
            .remove(0))
    }
    async fn get_team(&self, id: &str) -> AuthResult<Option<Team>> {
        self.get_team_value(&Value::from(id)).await
    }
    async fn get_team_value(&self, id: &Value) -> AuthResult<Option<Team>> {
        let id = self
            .organization_query(EntityRole::Team, "id", id.clone())?
            .field_value();
        let row = self
            .select_organization_rows(EntityRole::Team, &[("id".into(), id)])?
            .into_iter()
            .next();
        match row {
            Some(row) => Ok(self
                .output_record_refs(EntityRole::Team, vec![row])
                .await?
                .pop()),
            None => Ok(None),
        }
    }
    async fn update_team(&self, id: &str, update: UpdateTeam) -> AuthResult<Team> {
        self.update_team_value(&id.into(), update).await
    }
    async fn update_team_value(&self, id: &Value, update: UpdateTeam) -> AuthResult<Team> {
        let id = self
            .organization_query(EntityRole::Team, "id", id.clone())?
            .field_value();
        let mut patch = FieldMap::new();
        if let Some(name) = update.name {
            let _ = patch.insert("name".into(), name.into_field());
        }
        if let Some(organization_id) = update.organization_id {
            let _ = patch.insert("organizationId".into(), Value::from(organization_id));
        }
        if let Some(created_at) = update.created_at {
            let _ = patch.insert("createdAt".into(), Value::from(created_at));
        }
        if let Some(updated_at) = update.updated_at {
            let _ = patch.insert("updatedAt".into(), updated_at.into_field());
        }
        let patch = self
            .prepare_record_patch(EntityRole::Team, patch, update.additional_fields)
            .await?;
        let source = self
            .patch_organization_rows(
                EntityRole::Team,
                &[("id".into(), id)],
                patch.apply(FieldMap::new()),
                false,
            )?
            .ok_or_else(|| AuthError::not_found("Team not found"))?;
        Ok(self
            .output_record_refs(EntityRole::Team, vec![source])
            .await?
            .remove(0))
    }
    async fn delete_team(&self, id: &str) -> AuthResult<()> {
        self.delete_team_value(&id.into()).await
    }
    async fn delete_team_value(&self, id: &Value) -> AuthResult<()> {
        self.delete_team_with_context(id, None).await
    }
    async fn delete_team_for_organization_value(
        &self,
        id: &Value,
        organization_id: &Value,
    ) -> AuthResult<()> {
        self.delete_team_with_context(id, Some(organization_id))
            .await
    }
    async fn list_organization_teams(&self, organization_id: &str) -> AuthResult<Vec<Team>> {
        self.list_organization_teams_value(&Value::from(organization_id))
            .await
    }
    async fn list_organization_teams_value(
        &self,
        organization_id: &Value,
    ) -> AuthResult<Vec<Team>> {
        let schema = self.field_config(EntityRole::Team)?;
        let organization_id =
            self.organization_query(EntityRole::Team, "organizationId", organization_id.clone())?;
        let rows = self.select_organization_rows(
            EntityRole::Team,
            &[(
                schema.record_storage_key("organizationId").into(),
                organization_id.field_value(),
            )],
        )?;
        let rows = crate::query::paginate_memory(
            rows,
            Some(self.config.advanced.database.find_many_limit()),
            None,
        );
        self.output_record_refs(EntityRole::Team, rows).await
    }
    async fn count_organization_teams(&self, organization_id: &str) -> AuthResult<u64> {
        self.count_organization_teams_value(&Value::from(organization_id))
            .await
    }
    async fn count_organization_teams_value(&self, organization_id: &Value) -> AuthResult<u64> {
        let schema = self.field_config(EntityRole::Team)?;
        let organization_id =
            self.organization_query(EntityRole::Team, "organizationId", organization_id.clone())?;
        Ok(self
            .select_organization_rows(
                EntityRole::Team,
                &[(
                    schema.record_storage_key("organizationId").into(),
                    organization_id.field_value(),
                )],
            )?
            .len() as u64)
    }
    async fn list_user_teams(&self, user_id: &str) -> AuthResult<Vec<Team>> {
        self.list_user_teams_value(&user_id.into()).await
    }
    async fn list_user_teams_value(&self, user_id: &Value) -> AuthResult<Vec<Team>> {
        if self.config.advanced.database.joins == Some(true) {
            return self.joined_user_teams(user_id).await;
        }
        let schema = self.field_config(EntityRole::TeamMember)?;
        let team_schema = self.field_config(EntityRole::Team)?;
        let user_id = self.organization_query(EntityRole::TeamMember, "userId", user_id.clone())?;
        let runtime = self.model_fields.organization_join_schema();
        let join = crate::store::ResolvedJoin::resolve(
            (EntityRole::TeamMember, "teamMember", &schema),
            (EntityRole::Team, "team", &team_schema),
            &runtime,
            |_, _| false,
        )?;
        let rows = self.select_organization_rows(
            EntityRole::TeamMember,
            &[(
                schema.record_storage_key("userId").into(),
                user_id.field_value(),
            )],
        )?;
        let rows = crate::query::paginate_memory(
            rows,
            Some(self.config.advanced.database.find_many_limit()),
            None,
        );
        let continuation = Arc::new((join.clone(), schema, team_schema));
        let store = self.clone();
        let projected = self
            .project_record_sources_owned_batches_then(
                EntityRole::TeamMember,
                &self.field_config(EntityRole::TeamMember)?,
                rows.into_iter().map(RecordSource::Live).collect(),
                |_, fields| Ok(fields),
                move |ready: Vec<(usize, FieldMap)>| {
                    let continuation = continuation.clone();
                    let store = store.clone();
                    async move {
                        let (join, schema, team_schema) = continuation.as_ref();
                        let mut groups = Vec::new();
                        let mut teams = Vec::new();
                        for (index, member) in ready {
                            let from = join.fallback_from(
                                (EntityRole::TeamMember, "teamMember", schema),
                                &store.model_fields,
                            )?;
                            let owner = member.get(&from).cloned().unwrap_or_default();
                            let rows = if owner.is_null() || owner.is_undefined() {
                                Vec::new()
                            } else {
                                let (logical, physical) = join.fallback_target(
                                    (EntityRole::Team, "team", team_schema),
                                    &store.model_fields,
                                )?;
                                let value = if logical == "id" {
                                    store.memory_primary_id_query(&owner)?
                                } else {
                                    store.memory_field_query(team_schema, &logical, owner)?
                                };
                                let rows = store.select_organization_rows(
                                    EntityRole::Team,
                                    &[(physical, value)],
                                )?;
                                crate::query::paginate_memory(
                                    rows,
                                    Some(if join.many {
                                        store.config.advanced.database.find_many_limit()
                                    } else {
                                        1.0
                                    }),
                                    None,
                                )
                            };
                            groups.push(index);
                            teams.push(rows);
                        }
                        let pages = teams.iter().map(Vec::as_slice).collect();
                        let output = store.output_record_pages(EntityRole::Team, pages).await?;
                        Ok(groups.into_iter().zip(output).collect())
                    }
                },
            )
            .await?;
        projected
            .into_iter()
            .map(|rows| Team::from_membership_join(rows, join.many))
            .collect()
    }
    async fn get_team_member(
        &self,
        team_id: &str,
        user_id: &str,
    ) -> AuthResult<Option<TeamMember>> {
        self.get_team_member_value(&Value::from(team_id), &Value::from(user_id))
            .await
    }
    async fn get_team_member_value(
        &self,
        team_id: &Value,
        user_id: &Value,
    ) -> AuthResult<Option<TeamMember>> {
        let selectors = self.team_member_selectors(team_id, Some(user_id))?;
        let row = self
            .select_organization_rows(EntityRole::TeamMember, &selectors)?
            .into_iter()
            .next();
        Ok(self
            .output_record_refs(EntityRole::TeamMember, row.into_iter().collect())
            .await?
            .into_iter()
            .next())
    }
    async fn list_team_members(&self, team_id: &str) -> AuthResult<Vec<TeamMember>> {
        self.list_team_members_value(&Value::from(team_id)).await
    }
    async fn list_team_members_value(&self, team_id: &Value) -> AuthResult<Vec<TeamMember>> {
        let selectors = self.team_member_selectors(team_id, None)?;
        let rows = self.select_organization_rows(EntityRole::TeamMember, &selectors)?;
        let rows = crate::query::paginate_memory(
            rows,
            Some(self.config.advanced.database.find_many_limit()),
            None,
        );
        self.output_record_refs(EntityRole::TeamMember, rows).await
    }
    async fn count_team_members(&self, team_id: &str) -> AuthResult<u64> {
        self.count_team_members_value(&team_id.into()).await
    }
    async fn count_team_members_value(&self, team_id: &Value) -> AuthResult<u64> {
        let selectors = self.team_member_selectors(team_id, None)?;
        Ok(self
            .select_organization_rows(EntityRole::TeamMember, &selectors)?
            .len() as u64)
    }
    async fn add_team_member(
        &self,
        team_id: &crate::SchemaValue<String>,
        user_id: &str,
        maximum: Option<usize>,
    ) -> AuthResult<Option<TeamMember>> {
        self.add_team_member_value(&team_id.field_value(), &user_id.into(), maximum)
            .await
    }
    async fn add_team_member_value(
        &self,
        team_id: &Value,
        user_id: &Value,
        maximum: Option<usize>,
    ) -> AuthResult<Option<TeamMember>> {
        let key = crate::organization_fields::team_membership_key_values(team_id, user_id)?;
        if let Some(member) = self
            .find_team_member_by_key_or_pair(team_id, user_id, &key)
            .await?
        {
            return Ok(Some(member));
        }
        let id = self.organization_query(EntityRole::Team, "id", team_id.clone())?;
        let selectors = self.team_member_selectors(team_id, None)?;
        let (team, actual) = self.operation(|op| {
            let team = op
                .capture_table(EntityRole::Team)?
                .get_ref(&id)?
                .ok_or_else(|| AuthError::not_found("Team not found"))?;
            let actual = op
                .capture_table(EntityRole::TeamMember)?
                .select_refs(|row| Self::matches_team_member(row, &selectors))?
                .len();
            Ok((team, actual))
        })?;
        let mut prepared = self.prepare_team_reservation(team, actual, maximum).await?;
        let staged = if prepared.reserved {
            let staged = match self.stage_team_member(team_id, user_id, &key).await {
                Ok(staged) => staged,
                Err(error) => {
                    if maximum.is_some() {
                        self.release_prepared_team_seat(&mut prepared).await?;
                    }
                    return Err(error);
                }
            };
            if maximum.is_some() && !staged.created {
                self.release_prepared_team_seat(&mut prepared).await?;
            } else if maximum.is_none() && staged.created {
                self.increment_prepared_team_seat(&mut prepared).await?;
            }
            Some(staged)
        } else {
            None
        };
        let (existing, committed) = self.operation(|op| {
            let (existing, lookup) = self.prepare_team_member_lookup(op, team_id, user_id, &key)?;
            if let Some(row) = existing {
                return Ok((Some(row), false));
            }
            let state = op.capture_state()?;
            let actual = self
                .snapshot_table(&state, EntityRole::TeamMember)?
                .select_refs(|row| Self::matches_team_member(row, &selectors))?
                .len();
            if maximum.is_some_and(|maximum| actual >= maximum)
                && !prepared.is_current(self.snapshot_table(&state, EntityRole::Team)?, actual)?
            {
                return Ok((None, false));
            }
            if let Some(staged) = &staged
                && matches!(
                    self.config.advanced.database.generate_id(),
                    crate::id::IdGeneration::Serial
                )
                && self.snapshot_table(&state, EntityRole::TeamMember)?.len()?
                    != staged.base.len()?
            {
                return Err(AuthError::conflict(
                    "Team membership allocation changed while field transforms were pending",
                ));
            }
            let _ = prepared.apply(self.snapshot_table(&state, EntityRole::Team)?, actual)?;
            let plan = staged
                .as_ref()
                .map(|staged| {
                    self.snapshot_table(&state, EntityRole::TeamMember)?
                        .reconcile_with_plan(&staged.base, &staged.working)
                        .map(|(_, plan)| plan)
                })
                .transpose()?;
            let current_memberships = op.capture_table(EntityRole::TeamMember)?;
            if let Some(existing) = lookup.find(&current_memberships)? {
                return Ok((Some(existing), false));
            }
            let actual = current_memberships
                .select_refs(|row| Self::matches_team_member(row, &selectors))?
                .len();
            if maximum.is_some_and(|maximum| actual >= maximum)
                && !prepared.is_current(&op.capture_table(EntityRole::Team)?, actual)?
            {
                return Ok((None, false));
            }
            if let Some(staged) = &staged
                && matches!(
                    self.config.advanced.database.generate_id(),
                    crate::id::IdGeneration::Serial
                )
                && current_memberships.len()? != staged.base.len()?
            {
                return Err(AuthError::conflict(
                    "Team membership allocation changed while field transforms were pending",
                ));
            }
            let (source, fields) = prepared.apply(&op.capture_table(EntityRole::Team)?, actual)?;
            let memberships = plan
                .map(|plan| plan.apply(&current_memberships))
                .transpose()?;
            if let Some(memberships) = memberships {
                op.replace_table(EntityRole::TeamMember, memberships)?;
            }
            source.replace(fields)?;
            Ok((None, true))
        })?;
        if let Some(existing) = existing {
            return Ok(self
                .output_record_refs(EntityRole::TeamMember, vec![existing])
                .await?
                .into_iter()
                .next());
        }
        Ok(if committed {
            staged.map(|staged| staged.member)
        } else {
            None
        })
    }
    async fn remove_team_member(&self, team_id: &str, user_id: &str) -> AuthResult<()> {
        self.remove_team_member_value(&team_id.into(), &user_id.into())
            .await
    }
    async fn remove_team_member_value(&self, team_id: &Value, user_id: &Value) -> AuthResult<()> {
        let selected_by_pair = self.team_member_selectors(team_id, Some(user_id))?;
        let deleted = self.delete_organization_rows(EntityRole::TeamMember, &selected_by_pair)?;
        self.release_team_seats(team_id, deleted).await
    }
}
impl EphemeralStore {
    fn organization_role_selectors(
        &self,
        selectors: &FieldMap,
    ) -> AuthResult<Vec<(String, Value)>> {
        let schema = self.field_config(EntityRole::OrganizationRole)?;
        selectors
            .iter()
            .map(|(name, value)| {
                let key = if name == "id" {
                    name.clone()
                } else if schema.fields().contains_key(name) {
                    schema.record_storage_key(name).to_owned()
                } else {
                    return Err(AuthError::config(format!(
                        "Unknown organization role field {name}"
                    )));
                };
                Ok((
                    key,
                    self.organization_query(EntityRole::OrganizationRole, name, value.clone())?
                        .field_value(),
                ))
            })
            .collect()
    }

    async fn organization_role_patch(
        &self,
        mut update: UpdateOrganizationRole,
    ) -> AuthResult<super::fields::PreparedOrganizationFields> {
        let mut patch = FieldMap::new();
        if let Some(name) = update.role {
            let _ = patch.insert("role".into(), Value::from(name));
        }
        if let Some(permission) = update.permission {
            let value = permission
                .stringify()?
                .map(Value::String)
                .unwrap_or_default();
            let _ = patch.insert("permission".into(), value);
        }
        for field in better_auth_schema_registry::core_fields(EntityRole::OrganizationRole) {
            let name = better_auth_schema_registry::canonical_field_name(
                EntityRole::OrganizationRole,
                field.name,
            );
            if let Some(value) = update.additional_fields.remove(&name) {
                let _ = patch.entry(name).or_insert(value);
            }
        }
        self.prepare_record_patch(
            EntityRole::OrganizationRole,
            patch,
            update.additional_fields,
        )
        .await
    }
}

#[async_trait]
impl OrganizationRoleStore for EphemeralStore {
    async fn create_organization_role(
        &self,
        mut input: CreateOrganizationRole,
    ) -> AuthResult<OrganizationRole> {
        let schema = self.field_config(EntityRole::OrganizationRole)?;
        let organization_id = self.organization_query(
            EntityRole::OrganizationRole,
            "organizationId",
            input.organization_id.field_value(),
        )?;
        let role_name = self.organization_query(
            EntityRole::OrganizationRole,
            "role",
            Value::from(input.role.clone()),
        )?;
        let selectors = [
            (
                schema.record_storage_key("organizationId").into(),
                organization_id.field_value(),
            ),
            (
                schema.record_storage_key("role").into(),
                role_name.field_value(),
            ),
        ];
        if !self
            .select_organization_rows(EntityRole::OrganizationRole, &selectors)?
            .is_empty()
        {
            return Err(AuthError::bad_request("Role already exists"));
        }
        let permission = crate::SchemaValue::from_field(
            input
                .permission
                .stringify()?
                .map(Value::String)
                .unwrap_or_default(),
        );
        let mut role = OrganizationRole {
            field_order: Default::default(),
            additional_fields: Default::default(),
            id: Default::default(),
            organization_id: input.organization_id,
            role: (input.role).into(),
            permission,
            created_at: (Utc::now()).into(),
            updated_at: Default::default(),
        };
        if let Some(value) = input.additional_fields.remove("organizationId") {
            role.organization_id = crate::SchemaValue::from_field(value);
        }
        if let Some(value) = input.additional_fields.remove("role") {
            role.role = crate::SchemaValue::from_field(value);
        }
        if let Some(value) = input.additional_fields.remove("permission") {
            role.permission = crate::SchemaValue::Dynamic(value);
        }
        if let Some(value) = input.additional_fields.remove("createdAt") {
            role.created_at = crate::SchemaValue::from_field(value);
        }
        if let Some(value) = input.additional_fields.remove("updatedAt") {
            role.updated_at = crate::SchemaValue::from_field(value);
        }
        let role = self
            .create_record(EntityRole::OrganizationRole, role, input.additional_fields)
            .await?;
        let source = self.operation(|_| {
            if !self
                .select_organization_rows(EntityRole::OrganizationRole, &selectors)?
                .is_empty()
            {
                return Err(AuthError::bad_request("Role already exists"));
            }
            self.insert_organization_row(EntityRole::OrganizationRole, role)
        })?;
        Ok(self
            .output_record_refs(EntityRole::OrganizationRole, vec![source])
            .await?
            .remove(0))
    }
    async fn get_organization_role(&self, id: &str) -> AuthResult<Option<OrganizationRole>> {
        self.find_organization_role_by_fields(&[("id".into(), Value::from(id))].into())
            .await
    }
    async fn find_organization_role_by_fields(
        &self,
        selectors: &FieldMap,
    ) -> AuthResult<Option<OrganizationRole>> {
        let selectors = self.organization_role_selectors(selectors)?;
        let row = self
            .select_organization_rows(EntityRole::OrganizationRole, &selectors)?
            .into_iter()
            .next();
        match row {
            Some(row) => Ok(self
                .output_record_refs(EntityRole::OrganizationRole, vec![row])
                .await?
                .pop()),
            None => Ok(None),
        }
    }
    async fn list_organization_roles(
        &self,
        organization_id: &str,
    ) -> AuthResult<Vec<OrganizationRole>> {
        self.list_organization_roles_value(&Value::from(organization_id))
            .await
    }
    async fn list_organization_roles_value(
        &self,
        organization_id: &Value,
    ) -> AuthResult<Vec<OrganizationRole>> {
        let schema = self.field_config(EntityRole::OrganizationRole)?;
        let organization_id = self.organization_query(
            EntityRole::OrganizationRole,
            "organizationId",
            organization_id.clone(),
        )?;
        let rows = self.select_organization_rows(
            EntityRole::OrganizationRole,
            &[(
                schema.record_storage_key("organizationId").into(),
                organization_id.field_value(),
            )],
        )?;
        let rows = crate::query::paginate_memory(
            rows,
            Some(self.config.advanced.database.find_many_limit()),
            None,
        );
        self.output_record_refs(EntityRole::OrganizationRole, rows)
            .await
    }
    async fn query_organization_roles(
        &self,
        organization_id: &str,
        names: &[String],
    ) -> AuthResult<Vec<OrganizationRole>> {
        self.query_organization_roles_value(&Value::from(organization_id), names)
            .await
    }
    async fn query_organization_roles_value(
        &self,
        organization_id: &Value,
        names: &[String],
    ) -> AuthResult<Vec<OrganizationRole>> {
        let schema = self.field_config(EntityRole::OrganizationRole)?;
        let names = self
            .organization_query(
                EntityRole::OrganizationRole,
                "role",
                names
                    .iter()
                    .map(|name| Value::from(name.as_str()))
                    .collect::<Vec<_>>()
                    .into(),
            )?
            .field_value();
        let organization_id = self.organization_query(
            EntityRole::OrganizationRole,
            "organizationId",
            organization_id.clone(),
        )?;
        let rows = self.operation(|op| {
            op.capture_table(EntityRole::OrganizationRole)?
                .select_refs(|row| {
                    crate::memory_query::matches_all([0, 1], |clause| {
                        let (field, expected, operator) = if clause == 0 {
                            (
                                "organizationId",
                                organization_id.field_value(),
                                crate::WhereOperator::Eq,
                            )
                        } else {
                            ("role", names.clone(), crate::WhereOperator::In)
                        };
                        crate::memory_query::matches(
                            row.field(schema.record_storage_key(field))?.as_ref(),
                            &expected,
                            operator,
                            crate::WhereMode::Sensitive,
                        )
                    })
                })
        })?;
        let rows = crate::query::paginate_memory(
            rows,
            Some(self.config.advanced.database.find_many_limit()),
            None,
        );
        self.output_record_refs(EntityRole::OrganizationRole, rows)
            .await
    }
    async fn find_organization_role(
        &self,
        organization_id: &str,
        key: crate::store::OrganizationRoleKey<'_>,
    ) -> AuthResult<Option<OrganizationRole>> {
        self.find_organization_role_value(&Value::from(organization_id), key)
            .await
    }
    async fn find_organization_role_value(
        &self,
        organization_id: &Value,
        key: crate::store::OrganizationRoleKey<'_>,
    ) -> AuthResult<Option<OrganizationRole>> {
        let (key_field, key_value) = match key {
            crate::store::OrganizationRoleKey::Id(id) => ("id", Value::from(id)),
            crate::store::OrganizationRoleKey::Name(name) => ("role", Value::from(name)),
        };
        self.find_organization_role_by_fields(
            &[
                ("organizationId".into(), organization_id.clone()),
                (key_field.into(), key_value),
            ]
            .into(),
        )
        .await
    }
    async fn count_organization_roles(&self, organization_id: &str) -> AuthResult<u64> {
        self.count_organization_roles_value(&Value::from(organization_id))
            .await
    }
    async fn count_organization_roles_value(&self, organization_id: &Value) -> AuthResult<u64> {
        let schema = self.field_config(EntityRole::OrganizationRole)?;
        let organization_id = self.organization_query(
            EntityRole::OrganizationRole,
            "organizationId",
            organization_id.clone(),
        )?;
        Ok(self
            .select_organization_rows(
                EntityRole::OrganizationRole,
                &[(
                    schema.record_storage_key("organizationId").into(),
                    organization_id.field_value(),
                )],
            )?
            .len() as u64)
    }
    async fn update_organization_role(
        &self,
        id: &str,
        update: UpdateOrganizationRole,
    ) -> AuthResult<OrganizationRole> {
        self.update_organization_role_value(&id.into(), update)
            .await
    }
    async fn update_organization_role_value(
        &self,
        id: &Value,
        update: UpdateOrganizationRole,
    ) -> AuthResult<OrganizationRole> {
        let selectors = self.organization_role_selectors(&[("id".into(), id.clone())].into())?;
        let patch = self.organization_role_patch(update).await?;
        let role = self
            .patch_organization_rows(
                EntityRole::OrganizationRole,
                &selectors,
                patch.apply(FieldMap::new()),
                false,
            )?
            .ok_or_else(|| AuthError::not_found("Role not found"))?;
        self.output_record_refs(EntityRole::OrganizationRole, vec![role])
            .await?
            .pop()
            .ok_or_else(|| AuthError::not_found("Role not found"))
    }
    async fn update_organization_roles(
        &self,
        selectors: &FieldMap,
        update: UpdateOrganizationRole,
    ) -> AuthResult<u64> {
        let selectors = self.organization_role_selectors(selectors)?;
        let patch = self.organization_role_patch(update).await?;
        self.operation(|_| {
            let selected =
                self.select_organization_rows(EntityRole::OrganizationRole, &selectors)?;
            for row in &selected {
                row.apply_patch(patch.clone().apply(FieldMap::new()))?;
            }
            Ok(selected.len() as u64)
        })
    }

    async fn delete_organization_role(&self, id: &str) -> AuthResult<()> {
        self.delete_organization_role_by_fields(&[("id".into(), Value::from(id))].into())
            .await
    }
    async fn delete_organization_role_by_fields(&self, selectors: &FieldMap) -> AuthResult<()> {
        let selectors = self.organization_role_selectors(selectors)?;
        self.delete_organization_rows(EntityRole::OrganizationRole, &selectors)
            .map(|_| ())
    }
}

#[cfg(test)]
mod tests;
