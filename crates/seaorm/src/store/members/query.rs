use super::super::{instrumentation, pagination, plugin_rows, value_filter};
use super::*;
use better_auth_core::request_runtime::concurrent;
use better_auth_core::store::schema::EntityRole;
use better_auth_core::{
    WhereMode, WhereOperator,
    query::{validate_where_operand, where_operator},
};

struct BoundMemberQuery {
    organization: value_filter::BoundQueryField,
    filter: Option<(value_filter::BoundQueryField, WhereOperator)>,
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
        let filter = if let Some(field) = params
            .filter_field
            .as_deref()
            .filter(|field| !field.is_empty())
        {
            let value = params
                .filter_value
                .as_ref()
                .unwrap_or(&FieldValue::Undefined);
            let operator = where_operator(params.filter_operator.as_deref().unwrap_or("eq"));
            validate_where_operand(operator, value)?;
            Some((
                self.bind_organization_query_field(EntityRole::Member, field, value)?,
                operator,
            ))
        } else {
            None
        };
        Ok(BoundMemberQuery {
            organization,
            filter,
        })
    }

    fn resolve_member_query(
        &self,
        bound: BoundMemberQuery,
        sort: Option<&ListOrganizationMembersParams>,
    ) -> AuthResult<Select<Entity<O::Member>>> {
        let (column, value) = self.resolve_organization_query_field::<O::Member>(
            EntityRole::Member,
            bound.organization,
        )?;
        let mut predicates = vec![value_filter::QueryPredicate::equals(column, value)];
        if let Some((filter, operator)) = bound.filter {
            let (column, value) =
                self.resolve_organization_query_field::<O::Member>(EntityRole::Member, filter)?;
            predicates.push(value_filter::QueryPredicate::new(
                column,
                operator,
                WhereMode::Sensitive,
                value,
            ));
        }
        let mut query = plugin_rows::select_all::<Entity<O::Member>>();
        if let Some(params) = sort {
            query = self.sort_member_query(query, params)?;
        }
        Ok(query.filter(value_filter::all(
            predicates,
            self.connection().get_database_backend(),
        )?))
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
                let mut query = self.resolve_member_query(bound, Some(params))?;
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
                plugin_rows::count(self.connection(), self.resolve_member_query(bound, None)?)
                    .await
                    .map(|count| count as usize)
            },
        )
        .await;
        concurrent::adapter_result(count).await
    }
}
