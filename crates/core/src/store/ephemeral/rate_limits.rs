use super::*;
use crate::middleware::{EndpointRateLimit, RateLimitDecision};
use crate::query::{field_add, field_number};
use crate::store::{RateLimitStore, schema::EntityRole};
use crate::{WhereMode, WhereOperator};

impl EphemeralStore {
    async fn rate_limit_record(&self, key: &str) -> AuthResult<Option<FieldMap>> {
        let key = self.plugin_query_value(EntityRole::RateLimit, "key", key.into())?;
        let schema = self.model_fields.plugin_fields(EntityRole::RateLimit);
        let column = schema.record_storage_key("key");
        let rows = self
            .raw("rateLimit", "findMany", |state| {
                Ok(crate::query::paginate_memory(
                    state.rate_limits.select_refs(|row| {
                        crate::query::field_matches_equality(
                            row.get(column).unwrap_or(&Value::Undefined),
                            &key,
                        )
                    })?,
                    Some(self.config.advanced.database.find_many_limit()),
                    None,
                ))
            })
            .await?;
        Ok(self
            .project_plugin_refs(EntityRole::RateLimit, rows)
            .await?
            .into_iter()
            .next())
    }

    async fn consume_rate_limit_serialized(
        &self,
        key: &str,
        rule: EndpointRateLimit,
    ) -> AuthResult<(RateLimitDecision, Option<i64>)> {
        let window = rule.window * 1000.0;
        loop {
            let row = self.rate_limit_record(key).await?;
            let now = Utc::now().timestamp_millis();
            let Some(row) = row else {
                let created = self
                    .create_plugin_record(
                        EntityRole::RateLimit,
                        FieldMap::from_iter([
                            ("key".into(), key.into()),
                            ("count".into(), 1.into()),
                            ("lastRequest".into(), now.into()),
                        ]),
                        FieldMap::new(),
                    )
                    .await;
                if let Err(error) = created {
                    // Upstream retries creation failures only when the key now exists.
                    if self.rate_limit_record(key).await?.is_none() {
                        return Err(error);
                    }
                    continue;
                }
                return Ok((
                    RateLimitDecision {
                        allowed: true,
                        retry_after: None,
                    },
                    None,
                ));
            };
            let previous = row.get("lastRequest").cloned().unwrap_or_default();
            let reset = now as f64 - field_number(&previous)? >= window;
            let schema = self.model_fields.plugin_fields(EntityRole::RateLimit);
            let mut clauses = vec![
                (
                    schema.record_storage_key("key").to_owned(),
                    self.plugin_query_value(EntityRole::RateLimit, "key", key.into())?,
                    WhereOperator::Eq,
                ),
                (
                    schema.record_storage_key("lastRequest").to_owned(),
                    self.plugin_query_value(
                        EntityRole::RateLimit,
                        "lastRequest",
                        if reset {
                            previous
                        } else {
                            (now as f64 - window).into()
                        },
                    )?,
                    if reset {
                        WhereOperator::Lte
                    } else {
                        WhereOperator::Gt
                    },
                ),
            ];
            if !reset {
                clauses.push((
                    schema.record_storage_key("count").to_owned(),
                    self.plugin_query_value(
                        EntityRole::RateLimit,
                        "count",
                        rule.max_requests.into(),
                    )?,
                    WhereOperator::Lt,
                ));
            }
            let mut input = FieldMap::new();
            if reset {
                let _ = input.insert("count".into(), 1.into());
            }
            let _ = input.insert("lastRequest".into(), now.into());
            let patch = self
                .prepare_plugin_fields(EntityRole::RateLimit, input, false)
                .await?;
            crate::store::validate_increment_one_update(!reset, !patch.is_empty())?;
            let source = self
                .raw("rateLimit", "incrementOne", |state| {
                    let selected = state.rate_limits.try_select_refs(|row| {
                        crate::memory_query::matches_all(
                            clauses.iter(),
                            |(column, value, operator)| {
                                crate::memory_query::matches(
                                    row.get(column),
                                    value,
                                    *operator,
                                    WhereMode::Sensitive,
                                )
                            },
                        )
                    })?;
                    let Some(source) = selected.into_iter().next() else {
                        return Ok(None);
                    };
                    source.write(|row| {
                        if !reset {
                            let column = schema.record_storage_key("count");
                            let count = row.get(column).and_then(Value::as_f64).unwrap_or(0.0);
                            let _ = row.insert(column.to_owned(), (count + 1.0).into());
                        }
                        // Memory applies set after increments, including colliding physical fields.
                        row.extend(patch);
                        Ok(())
                    })?;
                    Ok(Some(source))
                })
                .await?;
            let updated = self
                .project_plugin_refs(EntityRole::RateLimit, source.into_iter().collect())
                .await?;
            if !updated.is_empty() {
                return Ok((
                    RateLimitDecision {
                        allowed: true,
                        retry_after: None,
                    },
                    reset.then_some(now),
                ));
            }
            if reset {
                continue;
            }
            let Some(fresh) = self.rate_limit_record(key).await? else {
                continue;
            };
            let previous = fresh.get("lastRequest").cloned().unwrap_or_default();
            if now as f64 - field_number(&previous)? >= window {
                continue;
            }
            let expires = field_number(&field_add(&previous, &window.into())?)?;
            return Ok((
                RateLimitDecision {
                    allowed: false,
                    retry_after: Some(
                        ((expires - Utc::now().timestamp_millis() as f64) / 1000.0).ceil(),
                    ),
                },
                None,
            ));
        }
    }

    async fn prune_rate_limits(&self, now: i64, cleanup_window: f64) -> AuthResult<()> {
        let _operation = self.rate_limit_operations.lock().await;
        let cutoff = self.plugin_query_value(
            EntityRole::RateLimit,
            "lastRequest",
            (now as f64 - cleanup_window * 1000.0).into(),
        )?;
        let schema = self.model_fields.plugin_fields(EntityRole::RateLimit);
        let column = schema.record_storage_key("lastRequest");
        self.raw("rateLimit", "deleteMany", |state| {
            state.rate_limits.try_retain(|row| {
                crate::memory_query::matches_all([column], |column| {
                    crate::memory_query::matches(
                        row.get(column),
                        &cutoff,
                        WhereOperator::Lt,
                        WhereMode::Sensitive,
                    )
                })
                .map(|expired| !expired)
            })
        })
        .await
    }
}

#[async_trait]
impl RateLimitStore for EphemeralStore {
    async fn consume_rate_limit(
        &self,
        key: &str,
        rule: EndpointRateLimit,
        cleanup_window: f64,
    ) -> AuthResult<RateLimitDecision> {
        let (decision, prune_at) = {
            // Serialize counter ownership across async field preparation without retaining data guards.
            let _operation = self.rate_limit_operations.lock().await;
            self.consume_rate_limit_serialized(key, rule).await?
        };
        if let Some(now) = prune_at {
            let store = self.clone();
            // A background handler may consume another counter before it runs this cleanup.
            crate::background::run_or_await_with_error_message(
                Some(Box::pin(async move {
                    store.prune_rate_limits(now, cleanup_window).await
                })),
                self.config.advanced.background_tasks.as_ref(),
                &self.config.logger,
                "Error pruning rate limit rows",
            )
            .await;
        }
        Ok(decision)
    }
}
