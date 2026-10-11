use super::{Entity, SeaOrmStore, models};
use crate::store::{
    joins, map_db_err,
    plugin_rows::{self, SqlRow},
};
use crate::{
    SeaOrmOrganizationModel, SeaOrmOrganizationSchema, SeaOrmPluginSchema, SeaOrmUserModel,
    schema::AuthSchema,
};
use better_auth_core::{
    AuthError, AuthResult, FieldMap, FieldValue, FromFieldMap, Invitation, Member, Organization,
    Team,
    store::{
        JoinValue, MemberUser, OrganizationDetails, OrganizationDetailsQuery, OrganizationKey,
        ResolvedJoin, schema::EntityRole,
    },
    user_fields::{AdapterRecord, UserConfig},
};
use sea_orm::{
    ColumnTrait, ConnectionTrait, DbBackend, EntityName, EntityTrait, Iterable, QueryFilter,
    QuerySelect, QueryTrait,
    sea_query::{Expr, ExprTrait, JoinType, Query, SelectStatement},
};

struct DetailRelation {
    role: EntityRole,
    fields: UserConfig,
    join: ResolvedJoin,
    limit: f64,
}

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

fn required_page(value: JoinValue<FieldMap>, name: &str) -> AuthResult<Vec<FieldMap>> {
    match value {
        JoinValue::Many(rows) => Ok(rows),
        JoinValue::One(None) => Err(AuthError::type_error(
            "Cannot read properties of null (reading 'map')",
        )),
        JoinValue::One(Some(_)) => Err(AuthError::type_error(format!(
            "{name}.map is not a function"
        ))),
    }
}

impl<S: AuthSchema, O: SeaOrmOrganizationSchema, P: SeaOrmPluginSchema> SeaOrmStore<S, O, P>
where
    S::User: SeaOrmUserModel,
    S::Session: crate::SeaOrmSessionModel,
    S::Account: crate::SeaOrmAccountModel,
    S::Verification: crate::SeaOrmVerificationModel,
{
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

    async fn project_detail_relation<M: SeaOrmOrganizationModel>(
        &self,
        parent: &mut FieldMap,
        name: &str,
        relation: &DetailRelation,
        rows: &[SqlRow],
    ) -> AuthResult<JoinValue<FieldMap>> {
        let backend = self.connection().get_database_backend();
        let mut pages =
            joins::project_child_pages(&relation.fields, vec![rows], backend, &|row: &SqlRow| {
                row.native_record(&relation.fields, backend, M::column)
                    .map(|record| record.with_id_output(&self.model_fields, relation.role))
            })
            .await?;
        let result = joins::relation_value(relation.join.many, pages.remove(0));
        let value = match &result {
            JoinValue::One(row) => row.clone().map_or(FieldValue::Null, FieldValue::from),
            JoinValue::Many(rows) => rows
                .iter()
                .cloned()
                .map(FieldValue::from)
                .collect::<Vec<_>>()
                .into(),
        };
        let _ = parent.insert(name.into(), value);
        Ok(result)
    }

    pub(super) async fn read_native_organization_details(
        &self,
        input: OrganizationDetailsQuery<'_>,
    ) -> AuthResult<Option<OrganizationDetails>> {
        let fields = self
            .organization_query_schema(EntityRole::Organization)?
            .adapter_fields(&[]);
        let backend = self.connection().get_database_backend();
        let (name, value) = match input.organization {
            OrganizationKey::Id(value) => ("id", value.into()),
            OrganizationKey::IdValue(value) => ("id", value.clone()),
            OrganizationKey::Slug(value) => ("slug", value.into()),
        };
        let predicate = self.organization_field_equals::<O::Organization>(
            EntityRole::Organization,
            name,
            &value,
        )?;
        let runtime = self.model_fields.organization_join_schema(self.config());
        let default_limit = self.config().advanced.database.find_many_limit();
        let relation = |role, model, limit| -> AuthResult<DetailRelation> {
            let child_fields = self.organization_query_schema(role)?.adapter_fields(&[]);
            let join = ResolvedJoin::resolve(
                (EntityRole::Organization, "organization", &fields),
                (role, model, &child_fields),
                &runtime,
                crate::store::model_names::table_matches::<S, O, P>,
            )?;
            Ok(DetailRelation {
                role,
                fields: child_fields,
                join,
                limit,
            })
        };
        let invitations = relation(EntityRole::Invitation, "invitation", default_limit)?;
        let members = relation(
            EntityRole::Member,
            "member",
            input.members_limit.unwrap_or(default_limit),
        )?;
        let teams = input
            .include_teams
            .then(|| relation(EntityRole::Team, "team", default_limit))
            .transpose()?;
        let mut parent = Entity::<O::Organization>::find()
            .filter(predicate)
            .limit(1)
            .into_query();
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
            &invitations,
            "invitation",
            "I_",
            "invitation_present",
        )?;
        self.model_fields.canonicalize_id(EntityRole::Member)?;
        add_join::<O::Organization, O::Member>(
            &mut query,
            &members,
            "member",
            "M_",
            "member_present",
        )?;
        if let Some(teams) = &teams {
            self.model_fields.canonicalize_id(EntityRole::Team)?;
            add_join::<O::Organization, O::Team>(&mut query, teams, "team", "T_", "team_present")?;
        }
        let rows = self
            .connection()
            .query_all(&query)
            .await
            .map_err(map_db_err)?
            .into_iter()
            .map(SqlRow::from)
            .collect::<Vec<_>>();
        let Some(first) = rows.first() else {
            return Ok(None);
        };
        let organization = first.prefixed("O_");
        let mut invitation_rows = Vec::new();
        let mut member_rows = Vec::new();
        let mut team_rows = Vec::new();
        for row in rows {
            invitation_rows.extend(row.optional_prefixed("I_", "invitation_present")?);
            member_rows.extend(row.optional_prefixed("M_", "member_present")?);
            if teams.is_some() {
                team_rows.extend(row.optional_prefixed("T_", "team_present")?);
            }
        }
        let invitation_rows = joins::selected_raw_children(
            invitation_rows.into_iter(),
            O::Invitation::column("id")?,
            invitations.join.many,
            invitations.limit,
        )?;
        let member_rows = joins::selected_raw_children(
            member_rows.into_iter(),
            O::Member::column("id")?,
            members.join.many,
            members.limit,
        )?;
        let team_rows = if let Some(teams) = &teams {
            joins::selected_raw_children(
                team_rows.into_iter(),
                O::Team::column("id")?,
                teams.join.many,
                teams.limit,
            )?
        } else {
            team_rows
        };
        let record = models::raw_record::<O::Organization>(
            &organization,
            &fields,
            backend,
            (&self.model_fields, EntityRole::Organization),
        )?;
        let record =
            self.detail_property::<O::Invitation>(record, &invitations, &invitation_rows)?;
        let record = self.detail_property::<O::Member>(record, &members, &member_rows)?;
        let record = if let Some(teams) = &teams {
            self.detail_property::<O::Team>(record, teams, &team_rows)?
        } else {
            record
        };
        let mut parent = fields
            .organization_output_records(vec![record], backend == DbBackend::Postgres)
            .await?
            .remove(0);
        let invitation_rows = self
            .project_detail_relation::<O::Invitation>(
                &mut parent,
                "invitation",
                &invitations,
                &invitation_rows,
            )
            .await?;
        let member_rows = self
            .project_detail_relation::<O::Member>(&mut parent, "member", &members, &member_rows)
            .await?;
        let team_rows = match teams {
            Some(teams) => Some(
                self.project_detail_relation::<O::Team>(&mut parent, "team", &teams, &team_rows)
                    .await?,
            ),
            None => None,
        };
        let member_rows = required_page(member_rows, "members")?
            .into_iter()
            .map(Member::from_field_values)
            .collect::<AuthResult<Vec<_>>>()?;
        let users = if member_rows.is_empty() {
            Vec::new()
        } else {
            let owners = member_rows
                .iter()
                .map(|member| member.user_id.field_value())
                .collect::<Vec<_>>();
            let (column, owners) = self.query_field_binding(
                EntityRole::User,
                &self.user_field_schema(),
                "id",
                &owners.into(),
                backend,
            )?;
            let (limit, _) =
                crate::store::pagination::sql_pagination(backend, Some(input.users_limit), None)?;
            let rows = plugin_rows::all(
                self.connection(),
                <S::User as SeaOrmUserModel>::Entity::find()
                    .filter(crate::store::value_filter::is_in(
                        S::User::field_column(&column)?,
                        &owners,
                        backend,
                    )?)
                    .limit(limit),
            )
            .await?;
            self.output_users(&rows, self.connection()).await?
        };
        let members = member_rows
            .into_iter()
            .map(|member| {
                let user = users
                    .iter()
                    .rev()
                    .find(|user| {
                        user.id
                            .field_value()
                            .same_value_zero(&member.user_id.field_value())
                    })
                    .ok_or_else(|| {
                        AuthError::internal("Unexpected error: User not found for member")
                    })?;
                Ok(MemberUser {
                    member,
                    user: better_auth_core::MemberUserView::from_user(user),
                })
            })
            .collect::<AuthResult<Vec<_>>>()?;
        let invitations = required_page(invitation_rows, "invitations")?
            .into_iter()
            .map(Invitation::from_field_values)
            .collect::<AuthResult<Vec<_>>>()?;
        let teams = match team_rows {
            None | Some(JoinValue::One(None)) => None,
            Some(JoinValue::One(Some(_))) => {
                return Err(AuthError::type_error("teams?.map is not a function"));
            }
            Some(JoinValue::Many(rows)) => Some(
                rows.into_iter()
                    .map(Team::from_field_values)
                    .collect::<AuthResult<Vec<_>>>()?,
            ),
        };
        for name in ["invitation", "member", "team"] {
            let _ = parent.shift_remove(name);
        }
        Ok(Some(OrganizationDetails {
            organization: Organization::from_field_values(parent)?,
            invitations,
            members,
            teams,
        }))
    }
}
