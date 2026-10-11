use crate::SeaOrmOrganizationModel;
use better_auth_core::store::schema::{EntityRole, resolve_field_name};
use better_auth_core::{
    AuthError, AuthResult, id::AdapterIdInput, plugin_runtime::ModelFields, user_fields::UserConfig,
};
use better_auth_core::{FieldMap, FieldValue, FromFieldMap};
use sea_orm::{ColumnTrait, ConnectionTrait, DbBackend, IdenStatic, QueryFilter, Select};

use super::plugin_rows::{self, SqlRow};
use super::value_filter::{self, QueryPredicate};

pub(super) type Entity<M> = <M as SeaOrmOrganizationModel>::Entity;

pub(super) fn extra_updated_at_column<M: SeaOrmOrganizationModel>(
    fields: &UserConfig,
) -> AuthResult<Option<M::Column>> {
    let column = M::column("auth_updated_at")?;
    let logical = M::core_field_name(&column).unwrap_or("auth_updated_at");
    if fields.fields().contains_key(logical) {
        return Ok(None);
    }
    Ok(
        (!fields.owns_adapter_column(&column.as_str(), |name| Ok(M::column(name)?.as_str()))?)
            .then_some(column),
    )
}

pub(super) fn raw_record<M: SeaOrmOrganizationModel>(
    row: &super::plugin_rows::SqlRow,
    fields: &UserConfig,
    backend: DbBackend,
    (runtime, role): (&ModelFields, EntityRole),
) -> AuthResult<better_auth_core::user_fields::AdapterRecord> {
    row.record::<Entity<M>>(fields, backend, M::column("id")?, M::column)
        .map(|record| record.with_id_output(runtime, role))
}

impl<S: crate::schema::AuthSchema, O: crate::SeaOrmOrganizationSchema, P: crate::SeaOrmPluginSchema>
    super::SeaOrmStore<S, O, P>
{
    pub(super) fn organization_query_schema(&self, role: EntityRole) -> AuthResult<UserConfig> {
        if role == EntityRole::TeamMember {
            Ok(self.model_fields.plugin_fields(role))
        } else {
            Ok(self.organization_fields()?.fields_for(role)?.clone())
        }
    }

    pub(super) fn bind_organization_query_field(
        &self,
        role: EntityRole,
        name: &str,
        value: &FieldValue,
    ) -> AuthResult<super::value_filter::BoundQueryField> {
        self.bind_query_field(
            role,
            &self.organization_query_schema(role)?,
            name,
            value,
            self.connection().get_database_backend(),
        )
    }

    pub(super) fn resolve_organization_query_field<M: SeaOrmOrganizationModel>(
        &self,
        role: EntityRole,
        bound: super::value_filter::BoundQueryField,
    ) -> AuthResult<(M::Column, FieldValue)> {
        let (column, value) = bound.resolve(role, &self.organization_query_schema(role)?)?;
        Ok((M::column(&column)?, value))
    }

    pub(super) fn organization_fields_equal<'a, M: SeaOrmOrganizationModel>(
        &self,
        role: EntityRole,
        selectors: impl IntoIterator<Item = (&'a str, &'a FieldValue)>,
    ) -> AuthResult<sea_orm::Condition> {
        let selectors = selectors
            .into_iter()
            .map(|(name, value)| self.bind_organization_query_field(role, name, value))
            .collect::<AuthResult<Vec<_>>>()?;
        let predicates = selectors
            .into_iter()
            .map(|bound| {
                let (column, value) = self.resolve_organization_query_field::<M>(role, bound)?;
                Ok(QueryPredicate::equals(column, value))
            })
            .collect::<AuthResult<Vec<_>>>()?;
        value_filter::all(predicates, self.connection().get_database_backend())
    }

    pub(super) fn organization_field_equals<M: SeaOrmOrganizationModel>(
        &self,
        role: better_auth_core::store::schema::EntityRole,
        name: &str,
        value: &FieldValue,
    ) -> AuthResult<sea_orm::sea_query::SimpleExpr> {
        let backend = self.connection().get_database_backend();
        let bound = self.bind_organization_query_field(role, name, value)?;
        let (column, value) = self.resolve_organization_query_field::<M>(role, bound)?;
        super::value_filter::equals(column, &value, backend)
    }

    pub(super) async fn find_organization_model<M: SeaOrmOrganizationModel>(
        &self,
        conn: &impl ConnectionTrait,
        role: EntityRole,
        id: &FieldValue,
    ) -> AuthResult<Option<SqlRow>> {
        plugin_rows::one(
            conn,
            super::plugin_rows::select_all::<Entity<M>>()
                .filter(self.organization_field_equals::<M>(role, "id", id)?),
        )
        .await
    }

    pub(super) async fn read_organization_model<M: SeaOrmOrganizationModel>(
        &self,
        conn: &impl ConnectionTrait,
        query: Select<Entity<M>>,
        role: EntityRole,
    ) -> AuthResult<Option<M::Record>>
    where
        M::Record: FromFieldMap,
    {
        let row = super::instrumentation::database_operation::<Entity<M>, _>(
            self.config(),
            "findOne",
            super::plugin_rows::one(conn, query),
        )
        .await?;
        let Some(row) = row else {
            return Ok(None);
        };
        record::<M>(
            &row,
            &self.organization_query_schema(role)?,
            conn.get_database_backend(),
            (&self.model_fields, role),
        )
        .await
        .map(Some)
    }

    pub(super) async fn update_organization_model<M: SeaOrmOrganizationModel>(
        &self,
        conn: &impl ConnectionTrait,
        role: EntityRole,
        id: &FieldValue,
        core: FieldMap,
        input: FieldMap,
        config: &UserConfig,
    ) -> AuthResult<M::Record>
    where
        M::Record: FromFieldMap,
    {
        self.update_organization_model_optional::<M>(conn, role, id, core, input, config)
            .await?
            .ok_or_else(|| AuthError::not_found("Organization record not found"))
    }

    pub(super) async fn update_organization_model_optional<M: SeaOrmOrganizationModel>(
        &self,
        conn: &impl ConnectionTrait,
        role: EntityRole,
        id: &FieldValue,
        core: FieldMap,
        input: FieldMap,
        config: &UserConfig,
    ) -> AuthResult<Option<M::Record>>
    where
        M::Record: FromFieldMap,
    {
        let selector = self.bind_organization_query_field(role, "id", id)?;
        let active = active::<M>(
            core,
            input,
            config,
            None,
            conn.get_database_backend(),
            self.config().advanced.database.generate_id(),
            (&self.model_fields, role),
        )
        .await?;
        let row = super::instrumentation::database_operation::<Entity<M>, _>(
            self.config(),
            "update",
            async {
                let (column, value) = self.resolve_organization_query_field::<M>(role, selector)?;
                let (query, filter) = active.update_where_returning(
                    conn.get_database_backend(),
                    [QueryPredicate::equals(column, value)],
                )?;
                super::updates::execute_update_returning_raw::<Entity<M>, _>(conn, query, filter)
                    .await
            },
        )
        .await?;
        let Some(row) = row else {
            return Ok(None);
        };
        record::<M>(
            &row.into(),
            config,
            conn.get_database_backend(),
            (&self.model_fields, role),
        )
        .await
        .map(Some)
    }
}

pub(crate) fn record_fields<M: SeaOrmOrganizationModel>(
    model: &M,
    fields: &UserConfig,
    backend: DbBackend,
) -> AuthResult<better_auth_core::user_fields::AdapterRecord> {
    let mut record = model.record_fields(fields)?;
    if backend == DbBackend::Sqlite {
        record.map_native_fields(fields, |name| {
            super::field_output::sqlite_json_output(
                &super::field_output::column_value::<M::Entity>(model, M::column(name)?),
            )
        })?;
    }
    record.map_storage_fields(
        fields,
        super::field_output::capabilities(backend),
        |name, field| {
            super::field_output::plugin_field_output(
                super::field_output::column_value::<M::Entity>(model, M::column(name)?),
                field,
                backend,
            )
        },
    )?;
    Ok(record)
}

pub(super) fn values<const N: usize>(fields: [(&str, FieldValue); N]) -> FieldMap {
    fields
        .into_iter()
        .map(|(name, value)| (name.to_owned(), value))
        .collect()
}

pub(super) fn with_id(mut fields: FieldMap, supplied: Option<FieldValue>) -> FieldMap {
    if let Some(id) = supplied {
        let _ = fields.insert("id".into(), id);
    }
    fields
}

pub(super) async fn active<M: SeaOrmOrganizationModel>(
    core: FieldMap,
    input: FieldMap,
    config: &UserConfig,
    model: Option<&str>,
    backend: sea_orm::DbBackend,
    policy: &better_auth_core::id::IdGeneration,
    (runtime, role): (&ModelFields, EntityRole),
) -> AuthResult<super::record_write::RecordWrite<Entity<M>>> {
    let core = core
        .into_iter()
        .map(|(name, value)| {
            let column = M::column(&name)?;
            Ok((
                M::core_field_name(&column).unwrap_or(&name).to_owned(),
                value,
            ))
        })
        .collect::<AuthResult<FieldMap>>()?;
    let backend_updated_at = if role == EntityRole::Organization {
        extra_updated_at_column::<M>(config)?.and_then(|column| {
            let logical = M::core_field_name(&column).unwrap_or("auth_updated_at");
            core.get(logical).cloned().map(|value| (column, value))
        })
    } else {
        None
    };
    let supplied = core.get("id").or_else(|| input.get("id")).cloned();
    runtime.begin_id_input(
        role,
        AdapterIdInput {
            force_allow_id: model.is_some() && supplied.is_some(),
            supports_native_uuid: backend == DbBackend::Postgres,
        },
    )?;
    let fields = config
        .organization_storage_fields_with_bound_id(
            core,
            input,
            model.is_some(),
            || match runtime.id_input_policy(role)? {
                Some(current) => match model {
                    Some(model) => policy.adapter_create_id_input(model, supplied.clone(), current),
                    None => supplied
                        .clone()
                        .map(|value| policy.adapter_id_input(value, current))
                        .transpose()
                        .map(Option::flatten),
                },
                None => Ok(supplied.clone()),
            },
            |storage_name, field, value| {
                let column = M::column(storage_name)?;
                let native_json = matches!(
                    column.def().get_column_type(),
                    sea_orm::ColumnType::Json | sea_orm::ColumnType::JsonBinary
                );
                crate::reference_id::input_binding(
                    storage_name,
                    field,
                    value,
                    policy,
                    M::column,
                    |_| native_json,
                    backend,
                )
            },
        )
        .await?;
    let mut active = super::record_write::RecordWrite::<Entity<M>>::default();
    if let Some((column, value)) = backend_updated_at {
        active.native_field(column, value);
    }
    active.apply_fields(fields, M::column)?;
    Ok(active)
}

pub(super) async fn insert<M: SeaOrmOrganizationModel, C: ConnectionTrait>(
    conn: &C,
    scope: super::create_readback::ReadbackScope<'_>,
    core: FieldMap,
    input: FieldMap,
    config: &UserConfig,
    policy: &better_auth_core::id::IdGeneration,
    (runtime, role, model): (&ModelFields, EntityRole, &str),
) -> AuthResult<M::Record>
where
    M::Record: FromFieldMap,
{
    let row = active::<M>(
        core,
        input,
        config,
        Some(model),
        conn.get_database_backend(),
        policy,
        (runtime, role),
    )
    .await?
    .insert_raw(
        conn,
        super::create_readback::CreateReadback {
            schema: config,
            policy,
            scope,
            column: M::column,
        },
    )
    .await?
    .ok_or_else(|| AuthError::internal("Organization record creation returned no record"))?;
    record::<M>(
        &row.into(),
        config,
        conn.get_database_backend(),
        (runtime, role),
    )
    .await
}

pub(super) async fn record<M: SeaOrmOrganizationModel>(
    row: &SqlRow,
    config: &UserConfig,
    backend: DbBackend,
    runtime: (&ModelFields, EntityRole),
) -> AuthResult<M::Record>
where
    M::Record: FromFieldMap,
{
    Ok(project::<M>(vec![row.clone()], config, backend, runtime)
        .await?
        .remove(0))
}

pub(super) async fn project<M: SeaOrmOrganizationModel>(
    rows: Vec<SqlRow>,
    config: &UserConfig,
    backend: DbBackend,
    runtime: (&ModelFields, EntityRole),
) -> AuthResult<Vec<M::Record>>
where
    M::Record: FromFieldMap,
{
    let fields = config.adapter_fields(&[]);
    let records = rows
        .iter()
        .map(|row| raw_record::<M>(row, &fields, backend, runtime))
        .collect::<AuthResult<Vec<_>>>()?;
    fields
        .organization_output_records(records, backend == DbBackend::Postgres)
        .await?
        .into_iter()
        .map(M::Record::from_field_values)
        .collect()
}

/// Resolve every configured field before accepting writes through this model.
pub(super) fn validate_fields<M: SeaOrmOrganizationModel>(
    entity: &str,
    fields: &UserConfig,
) -> AuthResult<()> {
    for (name, field) in fields.fields() {
        if name != "id" {
            let storage = resolve_field_name(field.field_name.as_deref(), name);
            let _ = M::column(storage).map_err(|error| {
                AuthError::config(format!("Organization schema {entity}.{name}: {error}"))
            })?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use better_auth_core::{
        AuthConfig, CreateOrganization, CreateOrganizationRole, UpdateOrganizationRole,
        organization_fields::OrganizationFields,
        store::{OrganizationRoleStore, OrganizationStore},
        user_fields::UserFieldConfig,
    };

    #[tokio::test]
    async fn native_role_dates_use_shared_declarations_for_create_update_and_readback() {
        let db = sea_orm::Database::connect("sqlite::memory:").await.unwrap();
        super::super::migrator::run_migrations(&db).await.unwrap();
        let store = super::super::SeaOrmStore::<super::super::bundled_schema::BundledSchema>::new(
            AuthConfig::new("organization-native-dates-secret-at-least-32-characters"),
            db,
        );
        let organization = store
            .create_organization(CreateOrganization::new("organization", "organization"))
            .await
            .unwrap();
        let created = store
            .create_organization_role(CreateOrganizationRole {
                organization_id: organization.id.clone(),
                role: "reader".into(),
                permission: FieldMap::new().into(),
                additional_fields: [("createdAt".into(), FieldValue::Undefined)].into(),
            })
            .await
            .unwrap();
        assert!(created.created_at.field_value().as_date().is_some());
        assert_eq!(created.updated_at.field_value(), FieldValue::Null);
        let changed = store
            .update_organization_role_value(
                &created.id.field_value(),
                UpdateOrganizationRole {
                    role: Some("writer".into()),
                    additional_fields: [
                        ("createdAt".into(), "2000-01-02T03:04:05.000Z".into()),
                        ("updatedAt".into(), FieldValue::Undefined),
                    ]
                    .into(),
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        assert_eq!(
            changed
                .created_at
                .field_value()
                .as_date()
                .unwrap()
                .milliseconds(),
            946_782_245_000.0
        );
        assert!(changed.updated_at.field_value().as_date().is_some());
        assert_eq!(
            store
                .get_organization_role(created.id.typed().unwrap())
                .await
                .unwrap()
                .unwrap(),
            changed
        );
        assert_eq!(
            store
                .list_organization_roles(organization.id.typed().unwrap())
                .await
                .unwrap(),
            vec![changed]
        );
        store
            .delete_organization_role(created.id.typed().unwrap())
            .await
            .unwrap();
        assert_eq!(
            store
                .count_organization_roles(organization.id.typed().unwrap())
                .await
                .unwrap(),
            0
        );
    }

    #[tokio::test]
    async fn native_role_queries_and_replacement_mappings_use_complete_declarations() {
        let db = sea_orm::Database::connect("sqlite::memory:").await.unwrap();
        super::super::migrator::run_migrations(&db).await.unwrap();
        let store = super::super::SeaOrmStore::<super::super::bundled_schema::BundledSchema>::new(
            AuthConfig::new("organization-query-schema-secret-at-least-32-characters"),
            db,
        );
        let mut ids = Vec::new();
        for id in ["first-org", "second-org"] {
            let _ = store
                .create_organization(CreateOrganization {
                    id: Some(id.into()),
                    ..CreateOrganization::new(id, id)
                })
                .await
                .unwrap();
            ids.push(
                store
                    .create_organization_role(CreateOrganizationRole {
                        organization_id: id.into(),
                        role: "reader".into(),
                        permission: FieldMap::new().into(),
                        additional_fields: FieldMap::new(),
                    })
                    .await
                    .unwrap()
                    .id,
            );
        }
        let selectors = [
            ("organizationId".into(), "first-org".into()),
            ("role".into(), "reader".into()),
        ]
        .into();
        assert_eq!(
            store
                .find_organization_role_by_fields(&selectors)
                .await
                .unwrap()
                .unwrap()
                .id,
            *ids.first().unwrap()
        );
        assert_eq!(
            store
                .update_organization_roles(
                    &selectors,
                    UpdateOrganizationRole {
                        role: Some("writer".into()),
                        ..Default::default()
                    }
                )
                .await
                .unwrap(),
            1
        );
        assert!(
            store
                .find_organization_role_by_fields(&selectors)
                .await
                .unwrap()
                .is_none()
        );

        store
            .configure_organization_fields(OrganizationFields {
                organization_role: UserConfig {
                    additional_fields: Some(
                        [(
                            "role".into(),
                            UserFieldConfig {
                                field_name: Some("organizationId".into()),
                                ..Default::default()
                            },
                        )]
                        .into(),
                    ),
                },
                ..Default::default()
            })
            .unwrap();
        let mapped = [("role".into(), "second-org".into())].into();
        let second = store
            .find_organization_role_by_fields(&mapped)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(second.id, *ids.last().unwrap());
        assert_eq!(second.role, "second-org");
        store
            .delete_organization_role_by_fields(&mapped)
            .await
            .unwrap();
        store
            .configure_organization_fields(OrganizationFields::default())
            .unwrap();
        assert!(
            store
                .get_organization_role(ids.last().unwrap().typed().unwrap())
                .await
                .unwrap()
                .is_none()
        );
        assert_eq!(
            store
                .get_organization_role(ids.first().unwrap().typed().unwrap())
                .await
                .unwrap()
                .unwrap()
                .role,
            "writer"
        );
    }
}
