use super::*;
use crate::store::{ResolvedJoin, TeamDetails};

impl EphemeralStore {
    pub(in crate::store::ephemeral) async fn read_team_details(
        &self,
        team_id: &Value,
        organization_id: Option<&Value>,
        include_members: bool,
        pending: &[(RowRef<FieldMap>, FieldMap)],
    ) -> AuthResult<Option<TeamDetails>> {
        let team_fields = self.field_config(EntityRole::Team)?;
        let team_id = self.organization_query_field(EntityRole::Team, "id", team_id.clone())?;
        let organization_id = organization_id
            .filter(|id| id.is_truthy())
            .map(|id| self.organization_query_field(EntityRole::Team, "organizationId", id.clone()))
            .transpose()?;
        let member_fields = self.field_config(EntityRole::TeamMember)?;
        let runtime = self.model_fields.organization_join_schema();
        let relation = include_members
            .then(|| {
                ResolvedJoin::resolve(
                    (EntityRole::Team, "team", &team_fields),
                    (EntityRole::TeamMember, "teamMember", &member_fields),
                    &runtime,
                    |_, _| false,
                )
            })
            .transpose()?;
        let limit = self.config.advanced.database.find_many_limit();
        let native = self.config.advanced.database.joins == Some(true) && include_members;
        let selected = self
            .raw("team", "findOne", |op| {
                let rows = op.capture_table(EntityRole::Team)?;
                let selected = rows.select_refs(|row| {
                    let mut source = RecordSource::Live(row.clone());
                    for (_, patch) in pending.iter().filter(|(source, _)| source.same_row(row)) {
                        source = source.with_patch(patch.clone());
                    }
                    let mut selectors = vec![team_id.clone()];
                    if let Some(id) = &organization_id {
                        selectors.push(id.clone());
                    }
                    crate::memory_query::matches_all(selectors.iter(), |(name, expected)| {
                        Ok(crate::query::field_matches_equality(
                            &source.field(name)?.unwrap_or_default(),
                            expected,
                        ))
                    })
                })?;
                let parents = selected
                    .into_iter()
                    .map(|row| {
                        let mut source = RecordSource::Live(row.clone());
                        for (_, patch) in pending.iter().filter(|(source, _)| source.same_row(&row))
                        {
                            source = source.with_patch(patch.clone());
                        }
                        source
                    })
                    .collect::<Vec<_>>();
                if native {
                    let relation = relation.as_ref().ok_or_else(|| {
                        AuthError::internal("Native Team relationship is missing")
                    })?;
                    let Some(mut group) = native_relationships(
                        parents,
                        &[(EntityRole::TeamMember, relation, limit)],
                        |role| op.capture_join_table(role),
                    )?
                    .into_iter()
                    .next() else {
                        return Ok(None);
                    };
                    let children = group.children.remove(0);
                    let source = RecordSource::joined(
                        group.parent,
                        [(
                            self.model_fields
                                .storage_model_name(EntityRole::TeamMember, "teamMember")
                                .to_owned(),
                            raw_relation(&children, relation.many),
                        )],
                    );
                    Ok(Some((source, Some(children))))
                } else {
                    let Some(source) = parents.into_iter().next() else {
                        return Ok(None);
                    };
                    Ok(Some((source, None)))
                }
            })
            .await?;
        let Some((source, members)) = selected else {
            return Ok(None);
        };
        let parent = self
            .project_record_sources(EntityRole::Team, &team_fields, vec![source])
            .await?
            .remove(0);
        let members = if let Some(relation) = relation {
            let members = if let Some(members) = members {
                members
            } else {
                let from =
                    relation.fallback_from((EntityRole::Team, "team", &team_fields), &runtime)?;
                let value = parent.get(&from).cloned().unwrap_or_default();
                if value.is_null() || value.is_undefined() {
                    Vec::new()
                } else {
                    let (logical, physical) = relation.fallback_target(
                        (EntityRole::TeamMember, "teamMember", &member_fields),
                        &runtime,
                    )?;
                    let value = self.memory_field_query(&member_fields, &logical, value)?;
                    self.raw(
                        "teamMember",
                        if relation.many { "findMany" } else { "findOne" },
                        |_| {
                            let rows = self.select_organization_rows(
                                EntityRole::TeamMember,
                                &[(physical, value)],
                            )?;
                            Ok(if relation.many {
                                crate::query::paginate_memory(rows, Some(limit), None)
                            } else {
                                rows.into_iter().take(1).collect()
                            })
                        },
                    )
                    .await?
                }
            };
            let mut pages = self
                .output_record_pages(EntityRole::TeamMember, vec![members.as_slice()])
                .await?;
            Some((pages.remove(0), relation.many))
        } else {
            None
        };
        TeamDetails::from_adapter_output(parent, members).map(Some)
    }
}
