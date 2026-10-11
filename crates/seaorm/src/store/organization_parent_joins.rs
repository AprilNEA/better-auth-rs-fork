use super::{
    SeaOrmStore,
    organization_models::{self as models, Entity},
    plugin_rows::{self, SqlRow},
};
use crate::{
    SeaOrmAccountModel, SeaOrmOrganizationModel, SeaOrmOrganizationSchema, SeaOrmPluginSchema,
    SeaOrmSessionModel, SeaOrmUserModel, SeaOrmVerificationModel, schema::AuthSchema,
};
use better_auth_core::{
    AuthError, AuthResult, FieldMap, FieldValue, FromFieldMap, Invitation,
    store::{InvitationOrganization, JoinValue, ResolvedJoin, schema::EntityRole},
    user_fields::UserConfig,
};
use sea_orm::{DbBackend, EntityName, EntityTrait, QueryFilter, QuerySelect, Select};

impl<S: AuthSchema, O: SeaOrmOrganizationSchema, P: SeaOrmPluginSchema> SeaOrmStore<S, O, P>
where
    S::User: SeaOrmUserModel,
    S::Session: SeaOrmSessionModel,
    S::Account: SeaOrmAccountModel,
    S::Verification: SeaOrmVerificationModel,
{
    pub(super) async fn list_member_organizations(
        &self,
        user_id: &FieldValue,
    ) -> AuthResult<Vec<JoinValue<FieldMap>>> {
        let query = Entity::<O::Member>::find().filter(
            self.organization_field_equals::<O::Member>(EntityRole::Member, "userId", user_id)?,
        );
        Ok(self
            .read_parent_organizations::<O::Member>(query, EntityRole::Member, "member")
            .await?
            .into_iter()
            .map(|(_, organization)| organization)
            .collect())
    }

    pub(super) async fn list_invitation_organizations(
        &self,
        email: &str,
    ) -> AuthResult<Vec<InvitationOrganization>> {
        let query = Entity::<O::Invitation>::find().filter(
            self.organization_field_equals::<O::Invitation>(
                EntityRole::Invitation,
                "email",
                &email.to_lowercase().into(),
            )?,
        );
        self.read_parent_organizations::<O::Invitation>(query, EntityRole::Invitation, "invitation")
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

    async fn read_parent_organizations<M: SeaOrmOrganizationModel>(
        &self,
        parent: Select<Entity<M>>,
        role: EntityRole,
        model: &str,
    ) -> AuthResult<Vec<(FieldMap, JoinValue<FieldMap>)>> {
        let backend = self.connection().get_database_backend();
        let parent = parent.limit(super::pagination::default_limit(self.config(), backend)?);
        let parent_fields = self.organization_query_schema(role)?;
        let organization_fields = self
            .organization_query_schema(EntityRole::Organization)?
            .adapter_fields(&[]);
        let runtime = self.model_fields.organization_join_schema(self.config());
        let relation = ResolvedJoin::resolve(
            (role, model, &parent_fields),
            (
                EntityRole::Organization,
                "organization",
                &organization_fields,
            ),
            &runtime,
            super::model_names::table_matches::<S, O, P>,
        )?;
        let (parents, children) = if self.config().advanced.database.joins == Some(true) {
            self.model_fields
                .canonicalize_id(EntityRole::Organization)?;
            let query = super::joins::joined_query::<Entity<M>, Entity<O::Organization>>(
                parent,
                (
                    M::column(&relation.from)?,
                    O::Organization::column(&relation.to)?,
                ),
                O::Organization::column("id")?,
            );
            let rows = super::joins::grouped_raw_rows(
                super::joins::joined_raw_rows(self.connection(), &query).await?,
                M::column("id")?,
            )?;
            let mut parents = Vec::with_capacity(rows.len());
            let mut children = Vec::with_capacity(rows.len());
            for (parent, organizations) in rows {
                parents.push(parent);
                children.push(super::joins::selected_raw_children(
                    organizations.into_iter(),
                    O::Organization::column("id")?,
                    relation.many,
                    self.config().advanced.database.find_many_limit(),
                )?);
            }
            (parents, Some(children))
        } else {
            (plugin_rows::all(self.connection(), parent).await?, None)
        };
        let entity = Entity::<O::Organization>::default();
        let physical = self
            .model_fields
            .storage_model_name(EntityRole::Organization, entity.table_name());
        let records = parents
            .iter()
            .enumerate()
            .map(|(index, parent)| {
                let record = models::raw_record::<M>(
                    parent,
                    &parent_fields,
                    backend,
                    (&self.model_fields, role),
                )?;
                if let Some(children) = &children {
                    let children = children.get(index).ok_or_else(|| {
                        AuthError::internal("Organization join lost its child page")
                    })?;
                    Ok(record.with_storage_property(
                        physical,
                        super::joins::raw_relation_value(
                            children,
                            &organization_fields,
                            relation.many,
                            O::Organization::column,
                        )?,
                    ))
                } else {
                    Ok(record)
                }
            })
            .collect::<AuthResult<Vec<_>>>()?;
        if let Some(children) = children {
            parent_fields
                .organization_output_records_batches_then(
                    records,
                    backend == DbBackend::Postgres,
                    |_, output| Ok(plugin_rows::ordered_output(&parent_fields, output)),
                    |ready| {
                        let children = &children;
                        let organization_fields = &organization_fields;
                        let relation = &relation;
                        async move {
                            let pages = ready
                                .iter()
                                .map(|(index, _)| {
                                    children.get(*index).map(Vec::as_slice).ok_or_else(|| {
                                        AuthError::internal(
                                            "Organization projection lost its joined page",
                                        )
                                    })
                                })
                                .collect::<AuthResult<Vec<_>>>()?;
                            let output = super::joins::project_child_pages(
                                organization_fields,
                                pages,
                                backend,
                                &|row: &SqlRow| {
                                    row.native_record(
                                        organization_fields,
                                        backend,
                                        O::Organization::column,
                                    )
                                    .map(|record| {
                                        record.with_id_output(
                                            &self.model_fields,
                                            EntityRole::Organization,
                                        )
                                    })
                                },
                            )
                            .await?;
                            Ok(ready
                                .into_iter()
                                .zip(output)
                                .map(|((index, parent), page)| {
                                    (
                                        index,
                                        (parent, super::joins::relation_value(relation.many, page)),
                                    )
                                })
                                .collect())
                        }
                    },
                )
                .await
        } else {
            parent_fields
                .organization_output_records_then(
                    records,
                    backend == DbBackend::Postgres,
                    |_, output| {
                        let relation = &relation;
                        let parent_fields = &parent_fields;
                        let organization_fields = &organization_fields;
                        let runtime = &runtime;
                        async move {
                            let from =
                                relation.fallback_from((role, model, parent_fields), runtime)?;
                            let value = output.get(&from).cloned().unwrap_or_default();
                            let organizations = self
                                .selected_parent_organizations(relation, organization_fields, value)
                                .await?;
                            Ok((
                                plugin_rows::ordered_output(parent_fields, output),
                                super::joins::relation_value(relation.many, organizations),
                            ))
                        }
                    },
                )
                .await
        }
    }

    async fn selected_parent_organizations(
        &self,
        relation: &ResolvedJoin,
        fields: &UserConfig,
        value: FieldValue,
    ) -> AuthResult<Vec<FieldMap>> {
        if value.is_null() || value.is_undefined() {
            return Ok(Vec::new());
        }
        let backend = self.connection().get_database_backend();
        let query = Entity::<O::Organization>::find().filter(
            self.organization_field_equals::<O::Organization>(
                EntityRole::Organization,
                &relation.to,
                &value,
            )?,
        );
        let rows = if relation.many {
            plugin_rows::all(
                self.connection(),
                query.limit(super::pagination::default_limit(self.config(), backend)?),
            )
            .await?
        } else {
            plugin_rows::one(self.connection(), query)
                .await?
                .into_iter()
                .collect()
        };
        let mut pages =
            super::joins::project_child_pages(fields, vec![rows.as_slice()], backend, &|row| {
                models::raw_record::<O::Organization>(
                    row,
                    fields,
                    backend,
                    (&self.model_fields, EntityRole::Organization),
                )
            })
            .await?;
        Ok(pages.remove(0))
    }
}
