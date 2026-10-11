use super::super::{instrumentation, pagination, plugin_rows, value_filter};
use super::*;
use better_auth_core::request_runtime::concurrent;
use better_auth_core::store::schema::EntityRole;

struct BoundMemberQuery {
    organization: value_filter::BoundQueryField,
    filter: Option<(value_filter::BoundQueryField, bool)>,
}

impl<S: AuthSchema, O: crate::SeaOrmOrganizationSchema, P: crate::SeaOrmPluginSchema>
    SeaOrmStore<S, O, P>
{
    fn bind_member_query(
        &self,
        params: &ListOrganizationMembersParams,
    ) -> AuthResult<BoundMemberQuery> {
        let organization = self.bind_organization_query_field(
            EntityRole::Member,
            "organizationId",
            &params.organization_id.field_value(),
        )?;
        let filter = bind_member_filter(
            params,
            &self.organization_fields()?.member,
            self.connection().get_database_backend(),
            self.config().advanced.database.generate_id(),
            &self.model_fields,
        )?;
        Ok(BoundMemberQuery {
            organization,
            filter,
        })
    }

    fn resolve_member_query(
        &self,
        bound: BoundMemberQuery,
        params: &ListOrganizationMembersParams,
    ) -> AuthResult<Select<Entity<O::Member>>> {
        let (column, value) = self.resolve_organization_query_field::<O::Member>(
            EntityRole::Member,
            bound.organization,
        )?;
        let query = plugin_rows::select_all::<Entity<O::Member>>().filter(value_filter::equals(
            column,
            &value,
            self.connection().get_database_backend(),
        )?);
        apply_member_filter::<O::Member>(
            query,
            params,
            &self.organization_fields()?.member,
            self.connection().get_database_backend(),
            self.config().advanced.database.generate_id(),
            bound.filter,
        )
    }

    fn sort_member_query(
        &self,
        query: Select<Entity<O::Member>>,
        params: &ListOrganizationMembersParams,
    ) -> AuthResult<Select<Entity<O::Member>>> {
        let Some(field) = params.sort_by.as_deref().filter(|field| !field.is_empty()) else {
            return Ok(query);
        };
        let schema = self.model_fields.runtime_fields(
            EntityRole::Member,
            &self.organization_query_schema(EntityRole::Member)?,
        )?;
        let (_, column) = value_filter::query_field_name(EntityRole::Member, &schema, field)?;
        let column = Expr::col(O::Member::column(column)?);
        Ok(if params.sort_direction.as_deref() == Some("desc") {
            query.order_by_desc(column)
        } else {
            query.order_by_asc(column)
        })
    }

    pub(super) async fn member_query_page(
        &self,
        params: &ListOrganizationMembersParams,
    ) -> AuthResult<Vec<Member>> {
        let bound = self.bind_member_query(params)?;
        let rows = instrumentation::database_operation::<Entity<O::Member>, _>(
            self.config(),
            "findMany",
            async {
                let query = self.resolve_member_query(bound, params)?;
                let mut query = self.sort_member_query(query, params)?;
                let (limit, offset) = pagination::sql_pagination(
                    self.connection().get_database_backend(),
                    params.limit,
                    params.offset,
                )?;
                let unbounded_offset = if limit.is_none() {
                    offset.unwrap_or(0)
                } else {
                    0
                };
                if let Some(offset) = offset.filter(|_| limit.is_some()) {
                    query = query.offset(offset);
                }
                if let Some(limit) = limit {
                    query = query.limit(limit);
                }
                let rows = plugin_rows::all(self.connection(), query).await?;
                let skip = std::cmp::min(unbounded_offset, rows.len() as u64) as usize;
                Ok(rows.into_iter().skip(skip).collect())
            },
        )
        .await;
        let rows = concurrent::adapter_result(rows).await?;
        models::project::<O::Member>(
            rows,
            &self.organization_fields()?.member,
            self.connection().get_database_backend(),
            (&self.model_fields, EntityRole::Member),
        )
        .await
    }

    pub(super) async fn member_query_count(
        &self,
        params: &ListOrganizationMembersParams,
    ) -> AuthResult<usize> {
        let bound = self.bind_member_query(params)?;
        let count = instrumentation::database_operation::<Entity<O::Member>, _>(
            self.config(),
            "count",
            async {
                self.resolve_member_query(bound, params)?
                    .count(self.connection())
                    .await
                    .map(|count| count as usize)
                    .map_err(map_db_err)
            },
        )
        .await;
        concurrent::adapter_result(count).await
    }
}
