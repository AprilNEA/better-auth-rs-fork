use async_trait::async_trait;
use better_auth_core::middleware::{EndpointRateLimit, RateLimitDecision};
use better_auth_core::query::{field_add, field_number};
use better_auth_core::store::{RateLimitStore, schema::EntityRole};
use better_auth_core::{AuthResult, AuthSchema, FieldMap};
use chrono::Utc;
use sea_orm::sea_query::{BinOper, Expr, ExprTrait};
use sea_orm::{ColumnTrait, ConnectionTrait, EntityTrait, QueryFilter, QuerySelect, QueryTrait};

use super::plugin_models::Entity;
use super::{SeaOrmStore, entities::rate_limit, instrumentation::database_operation, map_db_err};
use crate::{SeaOrmOrganizationSchema, SeaOrmPluginSchema};

pub(super) struct RateLimitCounters;

impl sea_orm_migration::MigrationName for RateLimitCounters {
    fn name(&self) -> &str {
        "m20261001_000001_rate_limit_counters"
    }
}

#[async_trait]
impl sea_orm_migration::MigrationTrait for RateLimitCounters {
    async fn up(&self, manager: &sea_orm_migration::SchemaManager) -> Result<(), sea_orm::DbErr> {
        manager
            .create_table(
                sea_orm::Schema::new(manager.get_database_backend())
                    .create_table_from_entity(rate_limit::Entity)
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &sea_orm_migration::SchemaManager) -> Result<(), sea_orm::DbErr> {
        manager
            .drop_table(
                sea_orm::sea_query::Table::drop()
                    .table(rate_limit::Entity)
                    .to_owned(),
            )
            .await
    }
}

impl<S: AuthSchema, O: SeaOrmOrganizationSchema, P: SeaOrmPluginSchema> SeaOrmStore<S, O, P> {
    async fn rate_limit_record(&self, key: &str) -> AuthResult<Option<FieldMap>> {
        let filter =
            self.plugin_equals::<P::RateLimit>(EntityRole::RateLimit, "key", key.into())?;
        let rows =
            database_operation::<Entity<P::RateLimit>, _>(self.config(), "findMany", async {
                self.connection()
                    .query_all_raw(
                        super::plugin_rows::select_all::<Entity<P::RateLimit>>()
                            .filter(filter)
                            .limit(super::pagination::default_limit(
                                self.config(),
                                self.connection().get_database_backend(),
                            )?)
                            .build(self.connection().get_database_backend()),
                    )
                    .await
                    .map_err(map_db_err)
            })
            .await?;
        Ok(self
            .project_plugin_rows::<P::RateLimit, FieldMap>(EntityRole::RateLimit, &rows)
            .await?
            .into_iter()
            .next())
    }

    async fn prune_rate_limits(&self, now: i64, cleanup_window: f64) -> AuthResult<()> {
        let (last_request, cutoff) = self.plugin_query_parameter::<P::RateLimit>(
            EntityRole::RateLimit,
            "lastRequest",
            (now as f64 - cleanup_window * 1000.0).into(),
        )?;
        database_operation::<Entity<P::RateLimit>, _>(self.config(), "deleteMany", async {
            let _ = Entity::<P::RateLimit>::delete_many()
                .filter(last_request.into_expr().lt(last_request.save_as(cutoff)))
                .exec(self.connection())
                .await
                .map_err(map_db_err)?;
            Ok(())
        })
        .await
    }
}

#[async_trait]
impl<S: AuthSchema, O: SeaOrmOrganizationSchema, P: SeaOrmPluginSchema> RateLimitStore
    for SeaOrmStore<S, O, P>
{
    async fn consume_rate_limit(
        &self,
        key: &str,
        rule: EndpointRateLimit,
        cleanup_window: f64,
    ) -> AuthResult<RateLimitDecision> {
        let window = rule.window * 1000.0;
        loop {
            let row = self.rate_limit_record(key).await?;
            let now = Utc::now().timestamp_millis();
            let Some(row) = row else {
                let insert = self
                    .create_plugin_record::<P::RateLimit>(
                        self.connection(),
                        super::create_readback::ReadbackScope::Direct(self.connection()),
                        EntityRole::RateLimit,
                        "rateLimit",
                        FieldMap::from_iter([
                            ("key".to_owned(), key.into()),
                            ("count".to_owned(), 1.into()),
                            ("lastRequest".to_owned(), now.into()),
                        ]),
                    )
                    .await;
                if let Err(error) = insert {
                    // Upstream retries a competing creation only when the key now exists.
                    if self.rate_limit_record(key).await?.is_none() {
                        return Err(error);
                    }
                    continue;
                }
                return Ok(RateLimitDecision {
                    allowed: true,
                    retry_after: None,
                });
            };
            let previous = row.get("lastRequest").cloned().unwrap_or_default();
            let reset = now as f64 - field_number(&previous)? >= window;
            let by_key = self.bind_plugin_query_field(EntityRole::RateLimit, "key", key.into())?;
            let previous = self.bind_plugin_query_field(
                EntityRole::RateLimit,
                "lastRequest",
                if reset {
                    previous
                } else {
                    (now as f64 - window).into()
                },
            )?;
            let maximum = if reset {
                None
            } else {
                Some(self.bind_plugin_query_field(
                    EntityRole::RateLimit,
                    "count",
                    rule.max_requests.into(),
                )?)
            };
            let increment = if reset {
                None
            } else {
                Some(self.plugin_column::<P::RateLimit>(EntityRole::RateLimit, "count")?)
            };
            let mut set = FieldMap::new();
            if reset {
                let _ = set.insert("count".to_owned(), 1.into());
            }
            let _ = set.insert("lastRequest".to_owned(), now.into());
            let mut fields = self
                .prepare_plugin_fields::<P::RateLimit>(
                    EntityRole::RateLimit,
                    "rateLimit",
                    set,
                    false,
                )
                .await?;
            let reselect =
                self.resolve_plugin_equals::<P::RateLimit>(EntityRole::RateLimit, by_key)?;
            let (last_request, previous) = self
                .resolve_plugin_query_parameter::<P::RateLimit>(EntityRole::RateLimit, previous)?;
            let mut guard = reselect.clone().and(last_request.into_expr().binary(
                if reset {
                    BinOper::SmallerThanOrEqual
                } else {
                    BinOper::GreaterThan
                },
                last_request.save_as(previous),
            ));
            if let Some(maximum) = maximum {
                let (count, maximum) = self.resolve_plugin_query_parameter::<P::RateLimit>(
                    EntityRole::RateLimit,
                    maximum,
                )?;
                guard = guard.and(count.into_expr().lt(count.save_as(maximum)));
            }
            if let Some(count) = increment {
                // Kysely replaces a colliding set assignment after applying all input policies.
                fields.not_set(count);
            }
            let mut query = fields.update(self.connection().get_database_backend())?;
            if let Some(count) = increment {
                query = query.col_expr(count, Expr::col(count).add(1));
            }
            let row = database_operation::<Entity<P::RateLimit>, _>(
                self.config(),
                "incrementOne",
                async {
                    super::updates::increment_returning_raw::<Entity<P::RateLimit>>(
                        self.connection(),
                        query.filter(guard.clone()),
                        guard,
                        reselect,
                    )
                    .await
                },
            )
            .await?;
            let updated = self
                .project_plugin_rows::<P::RateLimit, FieldMap>(
                    EntityRole::RateLimit,
                    row.as_slice(),
                )
                .await?;
            if !updated.is_empty() {
                if reset {
                    let store = self.clone();
                    // Only pruning failures use this catch. Counter writes already committed.
                    better_auth_core::background::run_or_await_with_error_message(
                        Some(Box::pin(async move {
                            store.prune_rate_limits(now, cleanup_window).await
                        })),
                        self.config.advanced.background_tasks.as_ref(),
                        &self.config.logger,
                        "Error pruning rate limit rows",
                    )
                    .await;
                }
                return Ok(RateLimitDecision {
                    allowed: true,
                    retry_after: None,
                });
            }
            if reset {
                continue;
            }
            let Some(fresh) = self.rate_limit_record(key).await? else {
                continue;
            };
            let last_request = fresh.get("lastRequest").cloned().unwrap_or_default();
            if now as f64 - field_number(&last_request)? >= window {
                continue;
            }
            let expires = field_number(&field_add(&last_request, &window.into())?)?;
            return Ok(RateLimitDecision {
                allowed: false,
                retry_after: Some(
                    ((expires - Utc::now().timestamp_millis() as f64) / 1000.0).ceil(),
                ),
            });
        }
    }
}
