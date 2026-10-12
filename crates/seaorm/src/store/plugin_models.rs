use crate::{SeaOrmPluginModel, schema::AuthSchema};
use better_auth_core::store::schema::{EntityRole, resolve_field_name};
use better_auth_core::{AuthResult, id::IdGeneration};
use better_auth_core::{FieldMap, FromFieldMap};
use sea_orm::{ColumnTrait, DbBackend, QueryResult};

pub(super) type Write<M> = super::record_write::RecordWrite<Entity<M>>;

pub(super) type Entity<M> = <M as SeaOrmPluginModel>::Entity;

impl<S: AuthSchema, O: crate::SeaOrmOrganizationSchema, P: crate::SeaOrmPluginSchema>
    super::SeaOrmStore<S, O, P>
{
    pub(super) fn plugin_column<M: SeaOrmPluginModel>(
        &self,
        role: EntityRole,
        name: &str,
    ) -> AuthResult<M::Column> {
        if name == "id" {
            return M::column("id");
        }
        let fields = self.model_fields.plugin_fields(role);
        let storage = fields.fields().get(name).map_or(name, |field| {
            resolve_field_name(field.field_name.as_deref(), name)
        });
        M::column(storage)
    }

    pub(super) fn validate_plugin_fields<M: SeaOrmPluginModel>(
        &self,
        role: EntityRole,
    ) -> AuthResult<()> {
        for name in self.model_fields.plugin_fields(role).fields().keys() {
            let _ = self.plugin_column::<M>(role, name)?;
        }
        let _ = M::column("id")?;
        Ok(())
    }

    pub(super) fn bind_plugin_query_field(
        &self,
        role: EntityRole,
        name: &str,
        value: better_auth_core::FieldValue,
    ) -> AuthResult<super::value_filter::BoundQueryField> {
        let fields = self.model_fields.plugin_fields(role);
        let backend = self.connection().get_database_backend();
        self.bind_query_field(role, &fields, name, &value, backend)
    }

    pub(super) fn resolve_plugin_query_field<M: SeaOrmPluginModel>(
        &self,
        role: EntityRole,
        bound: super::value_filter::BoundQueryField,
    ) -> AuthResult<(M::Column, better_auth_core::FieldValue)> {
        let (column, value) = bound.resolve(role, &self.model_fields.plugin_fields(role))?;
        Ok((M::column(&column)?, value))
    }

    pub(super) fn plugin_equals<M: SeaOrmPluginModel>(
        &self,
        role: EntityRole,
        name: &str,
        value: better_auth_core::FieldValue,
    ) -> AuthResult<sea_orm::sea_query::SimpleExpr> {
        let bound = self.bind_plugin_query_field(role, name, value)?;
        self.resolve_plugin_equals::<M>(role, bound)
    }

    pub(super) fn resolve_plugin_equals<M: SeaOrmPluginModel>(
        &self,
        role: EntityRole,
        bound: super::value_filter::BoundQueryField,
    ) -> AuthResult<sea_orm::sea_query::SimpleExpr> {
        let (column, value) = self.resolve_plugin_query_field::<M>(role, bound)?;
        super::value_filter::equals(column, &value, self.connection().get_database_backend())
    }

    pub(super) fn plugin_id_filter<M: SeaOrmPluginModel>(
        &self,
        role: EntityRole,
        id: &better_auth_core::SchemaValue<String>,
    ) -> AuthResult<sea_orm::sea_query::SimpleExpr> {
        self.plugin_equals::<M>(role, "id", id.field_value())
    }

    pub(super) async fn prepare_plugin_fields<M: SeaOrmPluginModel>(
        &self,
        role: EntityRole,
        model: &str,
        input: FieldMap,
        create: bool,
    ) -> AuthResult<Write<M>> {
        let fields = self.model_fields.plugin_fields(role);
        let backend = self.connection().get_database_backend();
        let policy = self.config().advanced.database.generate_id();
        let id_policy = better_auth_core::id::AdapterIdInput {
            force_allow_id: create && input.contains_key("id"),
            supports_native_uuid: backend == DbBackend::Postgres,
        };
        let mut supplied_id = input.get("id").cloned();
        let stored = self
            .model_fields
            .with_id_input(
                role,
                id_policy,
                fields.storage_fields_with_bound_id(
                    input,
                    create,
                    || {
                        let supplied = supplied_id.take();
                        let Some(current) = self.model_fields.id_input_policy(role)? else {
                            return Ok(supplied.filter(|value| !value.is_undefined()));
                        };
                        if create {
                            policy.adapter_create_id_input(model, supplied, current)
                        } else {
                            supplied
                                .map(|value| policy.adapter_id_input(value, current))
                                .transpose()
                                .map(Option::flatten)
                        }
                    },
                    |name, field, value| {
                        additional_field_input::<M>(name, field, value, policy, backend)
                    },
                ),
            )
            .await?;
        Write::<M>::from_fields(stored, M::column)
    }

    pub(super) async fn project_plugin_rows<M: SeaOrmPluginModel, T: FromFieldMap>(
        &self,
        role: EntityRole,
        rows: &[QueryResult],
    ) -> AuthResult<Vec<T>> {
        let backend = self.connection().get_database_backend();
        let fields = self.model_fields.plugin_fields(role);
        let records = rows
            .iter()
            .map(|row| super::plugin_rows::record::<M>(row, &fields, backend))
            .collect::<AuthResult<Vec<_>>>()?;
        self.model_fields
            .project_plugin_records(role, records, super::field_output::capabilities(backend))
            .await
    }
}

fn additional_field_input<M: SeaOrmPluginModel>(
    name: &str,
    field: &better_auth_core::user_fields::UserFieldConfig,
    value: better_auth_core::FieldValue,
    policy: &IdGeneration,
    backend: DbBackend,
) -> AuthResult<better_auth_core::FieldValue> {
    crate::reference_id::input_binding(
        name,
        field,
        value,
        policy,
        M::column,
        |name| {
            M::column(name).is_ok_and(|column| {
                matches!(
                    column.def().get_column_type(),
                    sea_orm::ColumnType::Json | sea_orm::ColumnType::JsonBinary
                )
            })
        },
        backend,
    )
}
