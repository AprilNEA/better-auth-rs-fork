use super::rows::{RecordSource, RowRef};
use super::*;
use crate::store::{
    JoinValue, MemberUser, OrganizationDetails, OrganizationDetailsQuery, OrganizationKey,
};
use better_auth_schema_registry::EntityRole;

#[cfg(test)]
mod detail_dependencies_tests;
mod details;
mod member_user;
mod organization_lists;
#[cfg(test)]
mod property_tests;
mod team_details;
#[cfg(test)]
mod tests;

struct NativeRelationship<T> {
    parent: FieldMap,
    children: Vec<Vec<RowRef<T>>>,
    ids: Vec<Vec<Value>>,
}

fn raw_relation<T: super::rows::ObjectRow + Clone + Send + 'static>(
    rows: &[RowRef<T>],
    many: bool,
) -> Value {
    if many {
        JoinValue::Many(rows.to_vec()).raw_value()
    } else {
        JoinValue::One(rows.first().cloned()).raw_value()
    }
}

fn native_relationships<T: super::rows::ObjectRow + Clone>(
    parents: Vec<RecordSource>,
    relations: &[(EntityRole, &crate::store::ResolvedJoin, f64)],
    mut capture_table: impl FnMut(EntityRole) -> AuthResult<super::table::TableRef<T>>,
) -> AuthResult<Vec<NativeRelationship<T>>> {
    let mut groups = indexmap::IndexMap::new();
    for parent in parents {
        let id = parent.field("id")?.unwrap_or_default().display_utf16()?;
        let group = match groups.entry(id.as_utf16().to_vec()) {
            indexmap::map::Entry::Occupied(entry) => entry.into_mut(),
            indexmap::map::Entry::Vacant(entry) => entry.insert(NativeRelationship {
                parent: parent.shallow_fields()?,
                children: vec![Vec::new(); relations.len()],
                ids: vec![Vec::new(); relations.len()],
            }),
        };
        for (((role, relation, limit), selected), ids) in relations
            .iter()
            .zip(&mut group.children)
            .zip(&mut group.ids)
        {
            let matches = capture_table(*role)?.select_refs(|row| {
                Ok(row
                    .field(&relation.to)?
                    .unwrap_or_default()
                    .strict_equals(&parent.field(&relation.from)?.unwrap_or_default()))
            })?;
            if !relation.many {
                *selected = matches.into_iter().take(1).collect();
                continue;
            }
            let mut added = 0_usize;
            for child in matches {
                if added as f64 >= *limit {
                    break;
                }
                let id = child.field("id")?.unwrap_or_default();
                if !ids.iter().any(|seen| seen.same_value_zero(&id)) {
                    ids.push(id);
                    selected.push(child);
                    added += 1;
                }
            }
        }
    }
    Ok(groups.into_values().collect())
}

impl EphemeralStore {
    pub(super) async fn joined_user_teams(&self, user_id: &Value) -> AuthResult<Vec<crate::Team>> {
        let member_schema = self.field_config(EntityRole::TeamMember)?;
        let team_schema = self.field_config(EntityRole::Team)?;
        let user_id = self.organization_query(EntityRole::TeamMember, "userId", user_id.clone())?;
        let runtime = self.model_fields.organization_join_schema();
        let join = crate::store::ResolvedJoin::resolve(
            (EntityRole::TeamMember, "teamMember", &member_schema),
            (EntityRole::Team, "team", &team_schema),
            &runtime,
            |_, _| false,
        )?;
        let limit = self.config.advanced.database.find_many_limit();
        let (members, teams) = self.operation(|op| {
            let rows = op
                .capture_table(EntityRole::TeamMember)?
                .select_refs(|row| {
                    Ok(
                        super::organization_rows::field(row, &member_schema, "userId")?
                            .strict_equals(&user_id.field_value()),
                    )
                })?
                .into_iter()
                .map(RecordSource::Live)
                .collect();
            let groups = native_relationships(rows, &[(EntityRole::Team, &join, limit)], |role| {
                op.capture_table(role)
            })?;
            Ok(crate::query::paginate_memory(groups, Some(limit), None)
                .into_iter()
                .map(|mut group| {
                    let children = group.children.remove(0);
                    let source = RecordSource::joined(
                        group.parent,
                        [(
                            self.model_fields
                                .storage_model_name(EntityRole::Team, "team")
                                .to_owned(),
                            raw_relation(&children, join.many),
                        )],
                    );
                    (source, children)
                })
                .unzip::<_, _, Vec<_>, Vec<_>>())
        })?;
        let teams = Arc::new(teams);
        let store = self.clone();
        let projected = self
            .project_record_sources_owned_batches_then(
                EntityRole::TeamMember,
                &member_schema,
                members,
                |_, fields| Ok(fields),
                move |ready: Vec<(usize, FieldMap)>| {
                    let teams = teams.clone();
                    let store = store.clone();
                    async move {
                        let pages = ready
                            .iter()
                            .map(|(index, _)| {
                                teams.get(*index).map(Vec::as_slice).ok_or_else(|| {
                                    AuthError::internal(
                                        "Team membership projection lost its stored join index",
                                    )
                                })
                            })
                            .collect::<AuthResult<Vec<_>>>()?;
                        let output = store.output_record_pages(EntityRole::Team, pages).await?;
                        Ok(ready
                            .into_iter()
                            .zip(output)
                            .map(|((index, _), rows)| (index, rows))
                            .collect())
                    }
                },
            )
            .await?;
        projected
            .into_iter()
            .map(|rows| crate::Team::from_membership_join(rows, join.many))
            .collect()
    }
}
