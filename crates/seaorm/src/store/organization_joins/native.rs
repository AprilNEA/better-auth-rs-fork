use super::{DetailChildren, DetailRelation, DetailRelations, Entity, SeaOrmStore};
use crate::store::{instrumentation::database_operation, joins, map_db_err, plugin_rows::SqlRow};
use crate::{
    SeaOrmOrganizationModel, SeaOrmOrganizationSchema, SeaOrmPluginSchema, SeaOrmUserModel,
    schema::AuthSchema,
};
use better_auth_core::{AuthResult, store::schema::EntityRole, user_fields::AdapterRecord};
use sea_orm::{
    ColumnTrait, ConnectionTrait, EntityName, EntityTrait, Iterable, QueryTrait, Select,
    sea_query::{Expr, ExprTrait, JoinType, Query, SelectStatement},
};

fn add_join<P: SeaOrmOrganizationModel, C: SeaOrmOrganizationModel>(
    query: &mut SelectStatement,
    relation: &DetailRelation,
    table: &'static str,
    prefix: &str,
    presence: &str,
) -> AuthResult<()> {
    let _ = query.join_as(
        JoinType::LeftJoin,
        Entity::<C>::default().table_ref(),
        table,
        Expr::col(("organization", P::column(&relation.join.from)?))
            .equals((table, C::column(&relation.join.to)?)),
    );
    joins::select_model::<Entity<C>>(query, table, prefix);
    let _ = query.expr_as(Expr::col((table, C::column("id")?)).is_not_null(), presence);
    Ok(())
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
        let mut parent = parent.into_query();
        let _ = parent.clear_selects();
        for column in <Entity<O::Organization> as EntityTrait>::Column::iter() {
            let _ = parent.expr(Expr::col(column.as_column_ref()));
        }
        let mut query = Query::select();
        let _ = query.from_subquery(parent, "organization");
        joins::select_model::<Entity<O::Organization>>(&mut query, "organization", "O_");
        self.model_fields.canonicalize_id(EntityRole::Invitation)?;
        add_join::<O::Organization, O::Invitation>(
            &mut query,
            &relations.invitations,
            "invitation",
            "I_",
            "invitation_present",
        )?;
        self.model_fields.canonicalize_id(EntityRole::Member)?;
        add_join::<O::Organization, O::Member>(
            &mut query,
            &relations.members,
            "member",
            "M_",
            "member_present",
        )?;
        if let Some(teams) = &relations.teams {
            self.model_fields.canonicalize_id(EntityRole::Team)?;
            add_join::<O::Organization, O::Team>(&mut query, teams, "team", "T_", "team_present")?;
        }
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
        let organization = first.prefixed("O_");
        let mut invitations = Vec::new();
        let mut members = Vec::new();
        let mut teams = Vec::new();
        for row in rows {
            invitations.extend(row.optional_prefixed("I_", "invitation_present")?);
            members.extend(row.optional_prefixed("M_", "member_present")?);
            if relations.teams.is_some() {
                teams.extend(row.optional_prefixed("T_", "team_present")?);
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
