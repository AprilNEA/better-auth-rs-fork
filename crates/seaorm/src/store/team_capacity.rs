use super::{
    create_readback::ReadbackScope,
    organization_models::{self as models, Entity},
    record_write::RecordWrite,
    value_filter::QueryPredicate,
};
use crate::SeaOrmOrganizationModel;
use better_auth_core::{
    AuthConfig, AuthResult, FieldValue, SchemaField, WhereMode, WhereOperator,
    plugin_runtime::ModelFields, store::schema::EntityRole, user_fields::UserConfig,
};
use sea_orm::{
    ConnectionTrait,
    sea_query::{Expr, ExprTrait},
};

type Runtime<'a> = (&'a ModelFields, EntityRole);

enum Guard {
    Below(u64),
    AtLeast(u64),
}

struct Selectors {
    id: super::value_filter::BoundQueryField,
    guard: Option<(Guard, super::value_filter::BoundQueryField)>,
}

fn counter_column<M: SeaOrmOrganizationModel>(
    fields: &UserConfig,
    role: EntityRole,
) -> AuthResult<M::Column> {
    let fields = fields.adapter_fields(&[]);
    let (_, column) = super::value_filter::query_field_name(role, &fields, "memberCount")?;
    M::column(column)
}

fn bind_selectors(
    backend: sea_orm::DbBackend,
    id: &FieldValue,
    guard: Option<Guard>,
    fields: &UserConfig,
    policy: &better_auth_core::id::IdGeneration,
    runtime: Runtime<'_>,
) -> AuthResult<Selectors> {
    let id = super::value_filter::bind_factory_query_field(
        runtime.0, runtime.1, fields, "id", id, policy, backend,
    )?;
    let guard = guard
        .map(|guard| {
            let value = match guard {
                Guard::Below(value) | Guard::AtLeast(value) => value,
            };
            super::value_filter::bind_factory_query_field(
                runtime.0,
                runtime.1,
                fields,
                "memberCount",
                &value.into_field(),
                policy,
                backend,
            )
            .map(|bound| (guard, bound))
        })
        .transpose()?;
    Ok(Selectors { id, guard })
}

impl Selectors {
    fn resolve<M: SeaOrmOrganizationModel>(
        self,
        fields: &UserConfig,
        role: EntityRole,
    ) -> AuthResult<Vec<QueryPredicate<M::Column>>> {
        let (column, value) = self.id.resolve(role, fields)?;
        let id = QueryPredicate::equals(M::column(&column)?, value);
        let guard = self
            .guard
            .map(|(guard, bound)| -> AuthResult<_> {
                let (column, value) = bound.resolve(role, fields)?;
                let column = M::column(&column)?;
                let operator = match guard {
                    Guard::Below(_) => WhereOperator::Lt,
                    Guard::AtLeast(_) => WhereOperator::Gte,
                };
                Ok(
                    QueryPredicate::new(column, operator, WhereMode::Sensitive, value)
                        .with_save_as(),
                )
            })
            .transpose()?;
        Ok(std::iter::once(id).chain(guard).collect())
    }
}

async fn write_and_output<M: SeaOrmOrganizationModel, C: ConnectionTrait>(
    conn: &C,
    scope: ReadbackScope<'_>,
    write: RecordWrite<Entity<M>>,
    selectors: Selectors,
    fields: &UserConfig,
    config: &AuthConfig,
    runtime: Runtime<'_>,
) -> AuthResult<bool> {
    let backend = conn.get_database_backend();
    let row =
        super::instrumentation::database_operation::<Entity<M>, _>(config, "incrementOne", async {
            let predicates = selectors.resolve::<M>(fields, runtime.1)?;
            match scope {
                ReadbackScope::Direct(pool) => {
                    super::updates::increment_returning_raw(pool, write, predicates).await
                }
                ReadbackScope::Transaction => {
                    super::updates::increment_returning_raw_with_connection(conn, write, predicates)
                        .await
                }
            }
        })
        .await?;
    let Some(row) = row else { return Ok(false) };
    let _ = fields
        .organization_output_records(
            vec![models::raw_record::<M>(
                &row.into(),
                fields,
                backend,
                runtime,
            )?],
            backend == sea_orm::DbBackend::Postgres,
        )
        .await?;
    Ok(true)
}

async fn update<M: SeaOrmOrganizationModel, C: ConnectionTrait>(
    conn: &C,
    scope: ReadbackScope<'_>,
    id: &FieldValue,
    (guard, delta): (Option<Guard>, f64),
    fields: &UserConfig,
    config: &AuthConfig,
    runtime: Runtime<'_>,
) -> AuthResult<bool> {
    let policy = config.advanced.database.generate_id();
    let selectors = bind_selectors(
        conn.get_database_backend(),
        id,
        guard,
        fields,
        policy,
        runtime,
    )?;
    let column = counter_column::<M>(fields, runtime.1)?;
    let mut write = RecordWrite::<Entity<M>>::default();
    write.expression(column, Expr::col(column).add(delta));
    write_and_output::<M, _>(conn, scope, write, selectors, fields, config, runtime).await
}

pub(super) async fn sync<M: SeaOrmOrganizationModel, C: ConnectionTrait>(
    conn: &C,
    id: &FieldValue,
    actual: u64,
    fields: &UserConfig,
    config: &AuthConfig,
    runtime: Runtime<'_>,
) -> AuthResult<()> {
    let policy = config.advanced.database.generate_id();
    let selectors = bind_selectors(
        conn.get_database_backend(),
        id,
        Some(Guard::Below(actual)),
        fields,
        policy,
        runtime,
    )?;
    let active = models::active::<M>(
        models::values([("member_count", (actual).into_field())]),
        Default::default(),
        fields,
        None,
        conn.get_database_backend(),
        policy,
        runtime,
    )
    .await?;
    better_auth_core::store::validate_increment_one_update(false, !active.is_empty())?;
    let _ = write_and_output::<M, _>(
        conn,
        ReadbackScope::Transaction,
        active,
        selectors,
        fields,
        config,
        runtime,
    )
    .await?;
    Ok(())
}

pub(super) async fn reserve<M: SeaOrmOrganizationModel, C: ConnectionTrait>(
    conn: &C,
    id: &FieldValue,
    maximum: usize,
    fields: &UserConfig,
    config: &AuthConfig,
    runtime: Runtime<'_>,
) -> AuthResult<bool> {
    update::<M, _>(
        conn,
        ReadbackScope::Transaction,
        id,
        (Some(Guard::Below(maximum as u64)), 1.0),
        fields,
        config,
        runtime,
    )
    .await
}

pub(super) async fn increment<M: SeaOrmOrganizationModel, C: ConnectionTrait>(
    conn: &C,
    id: &FieldValue,
    fields: &UserConfig,
    config: &AuthConfig,
    runtime: Runtime<'_>,
) -> AuthResult<()> {
    let _ = update::<M, _>(
        conn,
        ReadbackScope::Transaction,
        id,
        (None, 1.0),
        fields,
        config,
        runtime,
    )
    .await?;
    Ok(())
}

pub(super) async fn release<M: SeaOrmOrganizationModel, C: ConnectionTrait>(
    conn: &C,
    scope: ReadbackScope<'_>,
    id: &FieldValue,
    deleted: u64,
    fields: &UserConfig,
    config: &AuthConfig,
    runtime: Runtime<'_>,
) -> AuthResult<()> {
    if deleted > 0 {
        let _ = update::<M, _>(
            conn,
            scope,
            id,
            (Some(Guard::AtLeast(deleted)), -(deleted as f64)),
            fields,
            config,
            runtime,
        )
        .await?;
    }
    Ok(())
}
