use super::super::rows::Rows;
use super::*;
use crate::plugin_runtime::ModelFields;
use crate::store::ResolvedJoin;
use crate::user_fields::UserConfig;

struct DetailRelation {
    role: EntityRole,
    model: &'static str,
    fields: UserConfig,
    join: ResolvedJoin,
    limit: f64,
    table: fn(&State) -> &Rows<FieldMap>,
}

struct DetailChildren {
    invitations: Vec<RowRef<FieldMap>>,
    members: Vec<RowRef<FieldMap>>,
    teams: Option<Vec<RowRef<FieldMap>>>,
}

impl DetailRelation {
    fn raw_property(&self, models: &ModelFields, children: &[RowRef<FieldMap>]) -> (String, Value) {
        (
            models.storage_model_name(self.role, self.model).to_owned(),
            raw_relation(children, self.join.many),
        )
    }
}

impl EphemeralStore {
    async fn detail_relation(
        &self,
        parent: &mut FieldMap,
        parent_fields: &UserConfig,
        runtime: &ModelFields,
        relation: &DetailRelation,
        selected: Option<Vec<RowRef<FieldMap>>>,
    ) -> AuthResult<JoinValue<FieldMap>> {
        let rows = if let Some(rows) = selected {
            rows
        } else {
            let from = relation.join.fallback_from(
                (EntityRole::Organization, "organization", parent_fields),
                runtime,
            )?;
            let value = parent.get(&from).cloned().unwrap_or_default();
            if value.is_null() || value.is_undefined() {
                Vec::new()
            } else {
                let (logical, physical) = relation
                    .join
                    .fallback_target((relation.role, relation.model, &relation.fields), runtime)?;
                let value = self.organization_query(relation.role, &logical, value)?;
                self.raw(
                    relation.model,
                    if relation.join.many {
                        "findMany"
                    } else {
                        "findOne"
                    },
                    |state| {
                        let rows = (relation.table)(state).select_refs(|row| {
                            crate::query::field_matches_equality(
                                row.get(&physical).unwrap_or(&Value::Undefined),
                                &value.field_value(),
                            )
                        })?;
                        Ok(if relation.join.many {
                            crate::query::paginate_memory(rows, Some(relation.limit), None)
                        } else {
                            rows.into_iter().take(1).collect()
                        })
                    },
                )
                .await?
            }
        };
        let mut pages = self.output_record_pages(relation.role, vec![&rows]).await?;
        let rows = pages.remove(0);
        let result = if relation.join.many {
            JoinValue::Many(rows)
        } else {
            JoinValue::One(rows.into_iter().next())
        };
        let value = match &result {
            JoinValue::One(row) => row.clone().map_or(Value::Null, Value::from),
            JoinValue::Many(rows) => rows
                .iter()
                .cloned()
                .map(Value::from)
                .collect::<Vec<_>>()
                .into(),
        };
        // Later fallback joins read the parent after each preceding join replaces its logical property.
        let _ = parent.insert(relation.model.into(), value);
        Ok(result)
    }

    pub(in crate::store::ephemeral) async fn read_organization_details(
        &self,
        query: OrganizationDetailsQuery<'_>,
    ) -> AuthResult<Option<OrganizationDetails>> {
        let fields = self.field_config(EntityRole::Organization)?;
        let (field, value) = match query.organization {
            OrganizationKey::Id(id) => ("id", Value::from(id)),
            OrganizationKey::IdValue(id) => ("id", id.clone()),
            OrganizationKey::Slug(slug) => ("slug", Value::from(slug)),
        };
        let value = self.organization_query(EntityRole::Organization, field, value)?;
        let runtime = self.model_fields.organization_join_schema(&self.config);
        let default_limit = self.config.advanced.database.find_many_limit();
        let relation = |role, model, limit, table| -> AuthResult<DetailRelation> {
            let child_fields = self.field_config(role)?;
            let join = ResolvedJoin::resolve(
                (EntityRole::Organization, "organization", &fields),
                (role, model, &child_fields),
                &runtime,
                |_, _| false,
            )?;
            Ok(DetailRelation {
                role,
                model,
                fields: child_fields,
                join,
                limit,
                table,
            })
        };
        let invitations = relation(
            EntityRole::Invitation,
            "invitation",
            default_limit,
            |state: &State| &state.invitations,
        )?;
        let members = relation(
            EntityRole::Member,
            "member",
            query.members_limit.unwrap_or(default_limit),
            |state: &State| &state.members,
        )?;
        let teams = query
            .include_teams
            .then(|| {
                relation(EntityRole::Team, "team", default_limit, |state: &State| {
                    &state.teams
                })
            })
            .transpose()?;
        let native = self.config.advanced.database.joins == Some(true);
        let selected = self
            .raw("organization", "findOne", |state| {
                let parents = state.organizations.select_refs(|row| {
                    crate::query::field_matches_equality(
                        &organization_value(row, &fields, field),
                        &value.field_value(),
                    )
                })?;
                let Some(first) = parents.first() else {
                    return Ok(None);
                };
                if !native {
                    return Ok(Some((RecordSource::Live(first.clone()), None)));
                }
                let parents = parents
                    .iter()
                    .map(|parent| parent.read(|row| Ok(row.clone())))
                    .collect::<AuthResult<Vec<_>>>()?;
                let relations = [&invitations, &members]
                    .into_iter()
                    .chain(teams.as_ref())
                    .map(|relation| ((relation.table)(state), &relation.join, relation.limit))
                    .collect::<Vec<_>>();
                let group = native_relationships(parents, &relations)?
                    .into_iter()
                    .next()
                    .ok_or_else(|| {
                        AuthError::internal("Organization grouping lost its selected parent")
                    })?;
                let mut pages = group.children.into_iter();
                let children = DetailChildren {
                    invitations: pages.next().ok_or_else(|| {
                        AuthError::internal("Organization grouping lost its invitation page")
                    })?,
                    members: pages.next().ok_or_else(|| {
                        AuthError::internal("Organization grouping lost its member page")
                    })?,
                    teams: if teams.is_some() {
                        Some(pages.next().ok_or_else(|| {
                            AuthError::internal("Organization grouping lost its team page")
                        })?)
                    } else {
                        None
                    },
                };
                let properties = [
                    invitations.raw_property(&self.model_fields, &children.invitations),
                    members.raw_property(&self.model_fields, &children.members),
                ]
                .into_iter()
                .chain(
                    teams
                        .as_ref()
                        .zip(children.teams.as_ref())
                        .map(|(relation, rows)| relation.raw_property(&self.model_fields, rows)),
                );
                let source = RecordSource::joined(group.parent, properties);
                Ok(Some((source, Some(children))))
            })
            .await?;
        let Some((source, children)) = selected else {
            return Ok(None);
        };
        let mut parent = self
            .project_record_sources(EntityRole::Organization, &fields, vec![source])
            .await?
            .remove(0);
        let (selected_invitations, selected_members, selected_teams) = match children {
            Some(children) => (
                Some(children.invitations),
                Some(children.members),
                children.teams,
            ),
            None => (None, None, None),
        };
        let invitation_rows = self
            .detail_relation(
                &mut parent,
                &fields,
                &runtime,
                &invitations,
                selected_invitations,
            )
            .await?;
        let member_rows = self
            .detail_relation(&mut parent, &fields, &runtime, &members, selected_members)
            .await?;
        let team_rows = if let Some(relation) = &teams {
            Some(
                self.detail_relation(&mut parent, &fields, &runtime, relation, selected_teams)
                    .await?,
            )
        } else {
            None
        };
        // The plugin consumes members only after every adapter relation finishes projection.
        let member_rows = member_rows.into_required_page("members")?;
        let owners = member_rows
            .iter()
            .map(|member| member.get("userId").cloned().unwrap_or_default())
            .collect::<Vec<_>>();
        let users = if owners.is_empty() {
            Vec::new()
        } else {
            self.model_fields.begin_id_query(EntityRole::User)?;
            let owners = self
                .memory_primary_id_query(&owners.into())?
                .decode::<Vec<Value>>()?;
            let rows = self
                .raw("user", "findMany", |state| {
                    Ok(crate::query::paginate_memory(
                        state.users.select_refs(|user| {
                            owners
                                .iter()
                                .any(|owner| user.id.field_value().same_value_zero(owner))
                        })?,
                        Some(query.users_limit),
                        None,
                    ))
                })
                .await?;
            self.output_user_refs(rows).await?
        };
        Ok(Some(OrganizationDetails {
            organization: parent,
            invitations: invitation_rows,
            members: member_rows,
            users,
            teams: team_rows,
        }))
    }
}
