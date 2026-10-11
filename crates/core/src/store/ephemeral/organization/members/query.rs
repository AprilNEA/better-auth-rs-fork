use super::*;
use crate::store::ephemeral::rows::RowRef;
use crate::user_fields::UserConfig;

struct MemberQuery {
    schema: UserConfig,
    clauses: Vec<(String, crate::WhereOperator, Value)>,
}

fn declared_field<'a>(schema: &'a UserConfig, field: &str) -> AuthResult<&'a str> {
    if matches!(field, "id" | "_id") {
        return Ok("id");
    }
    crate::user_query::declared_field(field, schema)
        .map(|(logical, _)| logical)
        .ok_or_else(|| AuthError::config(format!("Field {field} not found in model member")))
}

impl EphemeralStore {
    fn bind_member_query(&self, params: &ListOrganizationMembersParams) -> AuthResult<MemberQuery> {
        let organization_id = self.organization_query(
            EntityRole::Member,
            "organizationId",
            params.organization_id.field_value(),
        )?;
        let schema = self
            .model_fields
            .runtime_fields(EntityRole::Member, &self.field_config(EntityRole::Member)?)?;
        let mut clauses = vec![(
            schema.record_storage_key("organizationId").to_owned(),
            crate::WhereOperator::Eq,
            organization_id.field_value(),
        )];
        if let Some(field) = params
            .filter_field
            .as_deref()
            .filter(|field| !field.is_empty())
        {
            let expected = params.filter_value.as_ref().unwrap_or(&Value::Undefined);
            let operator =
                crate::query::where_operator(params.filter_operator.as_deref().unwrap_or("eq"));
            crate::query::validate_where_operand(operator, expected)?;
            let field = declared_field(&schema, field)?;
            self.model_fields.begin_id_query(EntityRole::Member)?;
            let expected = if field == "id" {
                self.memory_primary_id_query(expected)?
            } else {
                self.memory_field_query(&schema, field, expected.clone())?
            };
            clauses.push((
                schema.record_storage_key(field).to_owned(),
                operator,
                expected,
            ));
        }
        Ok(MemberQuery { schema, clauses })
    }

    fn select_member_query(&self, query: &MemberQuery) -> AuthResult<Vec<RowRef<FieldMap>>> {
        let members = self.lock()?.members.select_refs(|_| true)?;
        let mut selected = Vec::with_capacity(members.len());
        for member in members {
            if crate::memory_query::matches_all(
                query.clauses.iter(),
                |(field, operator, expected)| {
                    let actual = member.read(|row| Ok(row.get(field).cloned()))?;
                    crate::memory_query::matches(
                        actual.as_ref(),
                        expected,
                        *operator,
                        crate::WhereMode::Sensitive,
                    )
                },
            )? {
                selected.push(member);
            }
        }
        Ok(selected)
    }

    pub(super) async fn member_query_page(
        &self,
        params: &ListOrganizationMembersParams,
    ) -> AuthResult<Vec<Member>> {
        let query = self.bind_member_query(params)?;
        let sources = crate::observability::database::with_database_operation(
            &self.config,
            "member",
            "findMany",
            async {
                let mut members = self.select_member_query(&query)?;
                if let Some(field) = params.sort_by.as_deref().filter(|field| !field.is_empty()) {
                    let descending = params.sort_direction.as_deref() == Some("desc");
                    crate::memory_sort::sort(&mut members, descending, |member| {
                        // The Memory adapter resolves sort fields only when its comparator runs.
                        let field = declared_field(&query.schema, field)?;
                        member.read(|row| Ok(organization_value(row, &query.schema, field)))
                    })?;
                }
                Ok(crate::query::paginate_memory(
                    members,
                    params.limit,
                    params.offset,
                ))
            },
        )
        .await;
        let sources = crate::request_runtime::concurrent::adapter_result(sources).await?;
        self.output_record_refs(EntityRole::Member, sources).await
    }

    pub(super) async fn member_query_count(
        &self,
        params: &ListOrganizationMembersParams,
    ) -> AuthResult<usize> {
        let query = self.bind_member_query(params)?;
        let count = crate::observability::database::with_database_operation(
            &self.config,
            "member",
            "count",
            async { self.select_member_query(&query).map(|rows| rows.len()) },
        )
        .await;
        crate::request_runtime::concurrent::adapter_result(count).await
    }
}
