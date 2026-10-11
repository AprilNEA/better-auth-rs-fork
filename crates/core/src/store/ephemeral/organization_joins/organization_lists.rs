//! Member and Invitation lists share relation resolution and retain complete Organization output.

use super::super::rows::Rows;
use super::*;
use crate::store::{InvitationOrganization, ResolvedJoin};

struct ParentModel {
    role: EntityRole,
    name: &'static str,
    rows: fn(&State) -> &Rows<FieldMap>,
}

impl EphemeralStore {
    pub(in crate::store::ephemeral) async fn joined_user_organizations(
        &self,
        user_id: &Value,
    ) -> AuthResult<Vec<JoinValue<FieldMap>>> {
        Ok(self
            .organization_relations(
                ParentModel {
                    role: EntityRole::Member,
                    name: "member",
                    rows: |state| &state.members,
                },
                ("userId", user_id.clone()),
            )
            .await?
            .into_iter()
            .map(|(_, organization)| organization)
            .collect())
    }

    pub(in crate::store::ephemeral) async fn joined_user_invitations(
        &self,
        email: &str,
    ) -> AuthResult<Vec<InvitationOrganization>> {
        self.organization_relations(
            ParentModel {
                role: EntityRole::Invitation,
                name: "invitation",
                rows: |state| &state.invitations,
            },
            ("email", email.to_lowercase().into()),
        )
        .await?
        .into_iter()
        .map(|(mut invitation, organization)| {
            let _ = invitation.shift_remove("organization");
            Ok(InvitationOrganization {
                invitation: Invitation::from_field_values(invitation)?,
                organization,
            })
        })
        .collect()
    }

    async fn organization_relations(
        &self,
        parent: ParentModel,
        (selector, value): (&str, Value),
    ) -> AuthResult<Vec<(FieldMap, JoinValue<FieldMap>)>> {
        let fields = self.field_config(parent.role)?;
        let value = self.organization_query(parent.role, selector, value)?;
        let child_fields = self.field_config(EntityRole::Organization)?;
        let runtime = self.model_fields.organization_join_schema(&self.config);
        let relation = ResolvedJoin::resolve(
            (parent.role, parent.name, &fields),
            (EntityRole::Organization, "organization", &child_fields),
            &runtime,
            |_, _| false,
        )?;
        let limit = self.config.advanced.database.find_many_limit();
        let native = self.config.advanced.database.joins == Some(true);
        let (sources, children) = self
            .raw(parent.name, "findMany", |state| {
                let rows = (parent.rows)(state).select_refs(|row| {
                    crate::query::field_matches_equality(
                        &organization_value(row, &fields, selector),
                        &value.field_value(),
                    )
                })?;
                if !native {
                    let sources = crate::query::paginate_memory(rows, Some(limit), None)
                        .into_iter()
                        .map(RecordSource::Live)
                        .collect::<Vec<_>>();
                    return Ok((sources, None));
                }
                let rows = rows
                    .iter()
                    .map(|row| row.read(|row| Ok(row.clone())))
                    .collect::<AuthResult<Vec<_>>>()?;
                let groups =
                    native_relationships(rows, &[(&state.organizations, &relation, limit)])?;
                let (sources, children) = crate::query::paginate_memory(groups, Some(limit), None)
                    .into_iter()
                    .map(|mut group| {
                        let children = group.children.remove(0);
                        let source = RecordSource::joined(
                            group.parent,
                            [(
                                self.model_fields
                                    .storage_model_name(EntityRole::Organization, "organization")
                                    .to_owned(),
                                raw_relation(&children, relation.many),
                            )],
                        );
                        (source, children)
                    })
                    .unzip::<_, _, Vec<_>, Vec<_>>();
                Ok((sources, Some(children)))
            })
            .await?;
        let continuation = std::sync::Arc::new((
            children,
            fields.clone(),
            child_fields,
            relation,
            runtime,
            parent,
        ));
        let store = self.clone();
        self.project_record_sources_owned_batches_then(
            continuation.5.role,
            &fields,
            sources,
            |_, fields| Ok(fields),
            move |ready: Vec<(usize, FieldMap)>| {
                let continuation = continuation.clone();
                let store = store.clone();
                async move {
                    let (children, fields, child_fields, relation, runtime, parent) =
                        continuation.as_ref();
                    let mut pages = Vec::with_capacity(ready.len());
                    for (index, output) in &ready {
                        let rows = if let Some(children) = children {
                            children.get(*index).cloned().ok_or_else(|| {
                                AuthError::internal(
                                    "Organization relationship lost its parent index",
                                )
                            })?
                        } else {
                            let from = relation
                                .fallback_from((parent.role, parent.name, fields), runtime)?;
                            let value = output.get(&from).cloned().unwrap_or_default();
                            if value.is_null() || value.is_undefined() {
                                Vec::new()
                            } else {
                                let (logical, physical) = relation.fallback_target(
                                    (EntityRole::Organization, "organization", child_fields),
                                    runtime,
                                )?;
                                let value = store.organization_query(
                                    EntityRole::Organization,
                                    &logical,
                                    value,
                                )?;
                                store
                                    .raw(
                                        "organization",
                                        if relation.many { "findMany" } else { "findOne" },
                                        |state| {
                                            let rows = state.organizations.select_refs(|row| {
                                                crate::query::field_matches_equality(
                                                    row.get(&physical).unwrap_or(&Value::Undefined),
                                                    &value.field_value(),
                                                )
                                            })?;
                                            Ok(if relation.many {
                                                crate::query::paginate_memory(
                                                    rows,
                                                    Some(limit),
                                                    None,
                                                )
                                            } else {
                                                rows.into_iter().take(1).collect()
                                            })
                                        },
                                    )
                                    .await?
                            }
                        };
                        pages.push(rows);
                    }
                    let output = store
                        .output_record_pages(
                            EntityRole::Organization,
                            pages.iter().map(Vec::as_slice).collect(),
                        )
                        .await?;
                    Ok(ready
                        .into_iter()
                        .zip(output)
                        .map(|((index, parent), rows)| {
                            let child = if relation.many {
                                JoinValue::Many(rows)
                            } else {
                                JoinValue::One(rows.into_iter().next())
                            };
                            (index, (parent, child))
                        })
                        .collect())
                }
            },
        )
        .await
    }
}
