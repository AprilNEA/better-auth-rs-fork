use super::{DetailChildren, DetailRelation, DetailRelations, Entity, SeaOrmStore};
use crate::store::{instrumentation::database_operation, joins, map_db_err, plugin_rows::SqlRow};
use crate::{
    SeaOrmOrganizationModel, SeaOrmOrganizationSchema, SeaOrmPluginSchema, SeaOrmUserModel,
    schema::AuthSchema,
};
use better_auth_core::{AuthResult, store::schema::EntityRole, user_fields::AdapterRecord};
use sea_orm::{
    ConnectionTrait, EntityName, IdenStatic, QueryTrait, Select,
    sea_query::{Asterisk, Expr, ExprTrait, JoinType, Query, SelectStatement},
};

fn add_join<P: SeaOrmOrganizationModel, C: SeaOrmOrganizationModel>(
    query: &mut SelectStatement,
    relation: &DetailRelation,
    table: &'static str,
) -> AuthResult<joins::ChildSelection> {
    let _ = query.join_as(
        JoinType::LeftJoin,
        Entity::<C>::default().table_ref(),
        table,
        Expr::col(("organization", P::column(&relation.join.from)?))
            .equals((table, C::column(&relation.join.to)?)),
    );
    joins::select_child_fields(
        query,
        table,
        Entity::<C>::default().table_name(),
        &relation.fields,
        C::column,
    )
}

impl<S: AuthSchema, O: SeaOrmOrganizationSchema, P: SeaOrmPluginSchema> SeaOrmStore<S, O, P>
where
    S::User: SeaOrmUserModel,
    S::Session: crate::SeaOrmSessionModel,
    S::Account: crate::SeaOrmAccountModel,
    S::Verification: crate::SeaOrmVerificationModel,
{
    pub(super) fn native_detail_record(
        &self,
        record: AdapterRecord,
        relations: &DetailRelations,
        children: &DetailChildren,
    ) -> AuthResult<AdapterRecord> {
        let record = self.detail_property::<O::Invitation>(
            record,
            &relations.invitations,
            &children.invitations,
        )?;
        let record =
            self.detail_property::<O::Member>(record, &relations.members, &children.members)?;
        match (&relations.teams, &children.teams) {
            (Some(relation), Some(rows)) => self.detail_property::<O::Team>(record, relation, rows),
            _ => Ok(record),
        }
    }

    fn detail_property<M: SeaOrmOrganizationModel>(
        &self,
        record: AdapterRecord,
        relation: &DetailRelation,
        rows: &[SqlRow],
    ) -> AuthResult<AdapterRecord> {
        let entity = Entity::<M>::default();
        let physical = self
            .model_fields
            .storage_model_name(relation.role, entity.table_name());
        Ok(record.with_storage_property(
            physical,
            joins::raw_relation_value(rows, &relation.fields, relation.join.many, M::column)?,
        ))
    }

    pub(super) async fn select_native_organization_details(
        &self,
        parent: Select<Entity<O::Organization>>,
        relations: &DetailRelations,
    ) -> AuthResult<Option<(SqlRow, DetailChildren)>> {
        let mut query = Query::select();
        let _ = query
            .from_subquery(parent.into_query(), "organization")
            .expr(Expr::col(("organization", Asterisk)));
        self.model_fields.canonicalize_id(EntityRole::Invitation)?;
        let invitation_selection = add_join::<O::Organization, O::Invitation>(
            &mut query,
            &relations.invitations,
            "invitation",
        )?;
        self.model_fields.canonicalize_id(EntityRole::Member)?;
        let member_selection =
            add_join::<O::Organization, O::Member>(&mut query, &relations.members, "member")?;
        let team_selection = if let Some(teams) = &relations.teams {
            self.model_fields.canonicalize_id(EntityRole::Team)?;
            Some(add_join::<O::Organization, O::Team>(
                &mut query, teams, "team",
            )?)
        } else {
            None
        };
        let rows =
            database_operation::<Entity<O::Organization>, _>(self.config(), "findOne", async {
                self.connection()
                    .query_all(&query)
                    .await
                    .map_err(map_db_err)
            })
            .await?
            .into_iter()
            .map(SqlRow::from)
            .collect::<Vec<_>>();
        let Some(first) = rows.first() else {
            return Ok(None);
        };
        let Some(organization) = joins::native_parent(
            first,
            O::Organization::column("id")?.as_str(),
            invitation_selection
                .aliases()
                .chain(member_selection.aliases())
                .chain(
                    team_selection
                        .iter()
                        .flat_map(joins::ChildSelection::aliases),
                ),
        )?
        else {
            return Ok(None);
        };
        let mut invitations = Vec::new();
        let mut members = Vec::new();
        let mut teams = Vec::new();
        for row in rows {
            invitations.extend(invitation_selection.read(&row)?);
            members.extend(member_selection.read(&row)?);
            if let Some(selection) = &team_selection {
                teams.extend(selection.read(&row)?);
            }
        }
        let invitations = joins::selected_raw_children(
            invitations.into_iter(),
            O::Invitation::column("id")?,
            relations.invitations.join.many,
            relations.invitations.limit,
        )?;
        let members = joins::selected_raw_children(
            members.into_iter(),
            O::Member::column("id")?,
            relations.members.join.many,
            relations.members.limit,
        )?;
        let teams = relations
            .teams
            .as_ref()
            .map(|relation| {
                joins::selected_raw_children(
                    teams.into_iter(),
                    O::Team::column("id")?,
                    relation.join.many,
                    relation.limit,
                )
            })
            .transpose()?;
        Ok(Some((
            organization,
            DetailChildren {
                invitations,
                members,
                teams,
            },
        )))
    }
}
