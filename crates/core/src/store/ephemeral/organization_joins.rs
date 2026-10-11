use super::native_joins::{native_relationships, raw_relation};
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
                op.capture_join_table(role)
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
