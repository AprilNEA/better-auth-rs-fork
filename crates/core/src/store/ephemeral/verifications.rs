use super::hooks::CommittedWrite;
use super::rows::{RecordSource, RowRef};
use super::*;
use crate::store::{
    VerificationCreateWriter,
    database_hooks::{DatabaseHookControl, VerificationUpdate},
};
use crate::{id::AdapterIdInput, store::schema::EntityRole};

impl EphemeralStore {
    pub(super) async fn output_verifications(
        &self,
        records: Vec<RecordSource>,
    ) -> AuthResult<Vec<VerificationView>> {
        let schema = self.config.verification.field_schema();
        let order = schema
            .adapter_fields(&[])
            .fields()
            .keys()
            .cloned()
            .collect::<Vec<_>>();
        Ok(self
            .project_record_sources(EntityRole::Verification, &schema, records)
            .await?
            .into_iter()
            .map(|fields| VerificationView::from_adapter_fields(fields.in_field_order(&order)))
            .collect())
    }

    pub(super) async fn output_verification(
        &self,
        record: RecordSource,
    ) -> AuthResult<VerificationView> {
        Ok(self.output_verifications(vec![record]).await?.remove(0))
    }

    pub(super) fn verification_query(
        &self,
        name: &str,
        value: impl Into<Value>,
    ) -> AuthResult<Value> {
        self.model_fields.begin_id_query(EntityRole::Verification)?;
        let schema = self.config.verification.field_schema().adapter_fields(&[]);
        if !schema.fields().contains_key(name) {
            return Err(AuthError::config(format!(
                "Unknown verification field: {name}"
            )));
        }
        if name == "id" {
            self.memory_primary_id_query(&value.into())
        } else {
            self.memory_field_query(&schema, name, value.into())
        }
    }

    pub(super) async fn verification_storage_fields(
        &self,
        input: FieldMap,
        create: bool,
    ) -> AuthResult<FieldMap> {
        let supplied = input.get("id").cloned();
        self.model_fields.begin_id_input(
            EntityRole::Verification,
            AdapterIdInput {
                force_allow_id: create && supplied.is_some(),
                supports_native_uuid: false,
            },
        )?;
        self.config
            .verification
            .field_schema()
            .storage_fields_with_bound_id(
                input,
                create,
                || {
                    let Some(policy) = self
                        .model_fields
                        .id_input_policy(EntityRole::Verification)?
                    else {
                        return Ok(supplied.clone());
                    };
                    if create {
                        self.config
                            .advanced
                            .database
                            .generate_id()
                            .adapter_create_id_input("verification", supplied.clone(), policy)
                    } else {
                        supplied
                            .clone()
                            .map(|value| {
                                self.config
                                    .advanced
                                    .database
                                    .generate_id()
                                    .adapter_id_input(value, policy)
                            })
                            .transpose()
                            .map(Option::flatten)
                    }
                },
                |_, field, value| self.memory_plugin_field_input(field, value),
            )
            .await
    }

    async fn create_verification_record(&self, input: FieldMap) -> AuthResult<VerificationView> {
        let mut record = self.verification_storage_fields(input, true).await?;
        let source = self
            .raw("verification", "create", |op| {
                let table = op.capture_table(EntityRole::Verification)?;
                if let Some(id) = self.next_serial_id(table.len()?) {
                    let _ = record.insert("id".into(), id);
                }
                table.push(record)
            })
            .await?;
        self.output_verification(RecordSource::Live(source)).await
    }

    pub(super) fn verification_field(
        &self,
        record: &RowRef<FieldMap>,
        name: &str,
    ) -> AuthResult<Option<Value>> {
        record.field(
            self.config
                .verification
                .field_schema()
                .record_storage_key(name),
        )
    }

    pub(super) async fn latest_verification_record(
        &self,
        identifier: &str,
    ) -> AuthResult<Option<RowRef<FieldMap>>> {
        let bound_identifier = self.verification_query("identifier", identifier)?;
        let records = self
            .raw("verification", "findMany", |op| {
                let mut records =
                    op.capture_table(EntityRole::Verification)?
                        .select_refs(|row| {
                            Ok(self
                                .verification_field(row, "identifier")?
                                .unwrap_or_default()
                                .strict_equals(&bound_identifier))
                        })?;
                crate::memory_sort::sort(&mut records, true, |row| {
                    Ok(self
                        .verification_field(row, "createdAt")?
                        .unwrap_or_default())
                })?;
                Ok(records)
            })
            .await?;
        Ok(records.into_iter().next())
    }
}

#[async_trait]
impl VerificationStore<StatelessSchema> for EphemeralStore {
    async fn before_create_runtime_verification(
        &self,
        input: &mut CreateVerification,
    ) -> AuthResult<()> {
        if self
            .before_create_runtime_verification_optional(input)
            .await?
        {
            Ok(())
        } else {
            Err(AuthError::forbidden(
                "verification creation cancelled by database hook",
            ))
        }
    }

    async fn before_create_runtime_verification_optional(
        &self,
        input: &mut CreateVerification,
    ) -> AuthResult<bool> {
        let transaction = EphemeralTransaction {
            store: self.clone(),
        };
        let context = self.hook_context(&transaction);
        for hook in &self.hooks {
            if crate::observability::database::with_database_hook(
                context.config,
                hook.hook_metadata(),
                crate::observability::database::DatabaseHook::BeforeCreateVerification,
                hook.before_create_verification(input, &context),
            )
            .await?
                == DatabaseHookControl::Cancel
            {
                return Ok(false);
            }
        }
        Ok(true)
    }
    async fn after_create_runtime_verification(
        &self,
        record: Option<&VerificationView>,
        request: Option<crate::hooks::RequestHookContext>,
    ) -> AuthResult<()> {
        self.after_with_request(
            CommittedWrite::VerificationCreated(record.cloned()),
            request,
        )
        .await
    }

    async fn reserve_verification(&self, id: &str, input: CreateVerification) -> AuthResult<bool> {
        let result = async {
            self.create_verification_record(input.into_reservation(id).fields()?)
                .await
        }
        .await;
        // The fallback observes rows left by input, persistence, or output failures.
        if let Err(error) = result {
            let bound = self.verification_query("id", id)?;
            let found = self
                .raw("verification", "findOne", |op| {
                    Ok(op
                        .capture_table(EntityRole::Verification)?
                        .select_refs(|record| {
                            Ok(record
                                .field("id")?
                                .unwrap_or_default()
                                .strict_equals(&bound))
                        })?
                        .into_iter()
                        .next())
                })
                .await?;
            let Some(found) = found else {
                return Err(error);
            };
            let _ = self.output_verification(RecordSource::Live(found)).await?;
            return Ok(false);
        }
        Ok(true)
    }

    async fn create_verification(&self, input: CreateVerification) -> AuthResult<VerificationView> {
        self.create_verification_optional(input)
            .await?
            .ok_or_else(|| AuthError::internal("Verification creation returned no record"))
    }
    async fn create_verification_optional(
        &self,
        input: CreateVerification,
    ) -> AuthResult<Option<VerificationView>> {
        self.create_verification_with_writer(input, None).await
    }
    async fn create_verification_with_writer(
        &self,
        input: CreateVerification,
        writer: Option<VerificationCreateWriter>,
    ) -> AuthResult<Option<VerificationView>> {
        let mut input = input.with_timestamps(Utc::now().into());
        if !self
            .before_create_runtime_verification_optional(&mut input)
            .await?
        {
            return Ok(None);
        }
        let projected = self.create_verification_record(input.fields()?).await?;
        if let Some(writer) = writer {
            writer(projected.fields()?).await?;
        }
        self.after_create_runtime_verification(
            Some(&projected),
            crate::hooks::current_request_hook_context(),
        )
        .await?;
        Ok(Some(projected))
    }

    async fn get_verification_including_expired(
        &self,
        identifier: &str,
    ) -> AuthResult<Option<VerificationView>> {
        let record = self.latest_verification_record(identifier).await?;
        futures_util::future::OptionFuture::from(
            record.map(|row| self.output_verification(RecordSource::Live(row))),
        )
        .await
        .transpose()
    }
    async fn get_verification(
        &self,
        identifier: &str,
        value: &str,
    ) -> AuthResult<Option<VerificationView>> {
        let bound_identifier = self.verification_query("identifier", identifier)?;
        let bound_value = self.verification_query("value", value)?;
        let record = self
            .raw("verification", "findOne", |op| {
                Ok(op
                    .capture_table(EntityRole::Verification)?
                    .select_refs(|row| {
                        crate::memory_query::matches_all(
                            [("identifier", &bound_identifier), ("value", &bound_value)],
                            |(name, value)| {
                                Ok(self
                                    .verification_field(row, name)?
                                    .unwrap_or_default()
                                    .strict_equals(value))
                            },
                        )
                    })?
                    .into_iter()
                    .next())
            })
            .await?;
        futures_util::future::OptionFuture::from(
            record.map(|record| self.output_verification(RecordSource::Live(record))),
        )
        .await
        .transpose()
    }
    async fn get_verification_by_value(&self, value: &str) -> AuthResult<Option<VerificationView>> {
        let bound_value = self.verification_query("value", value)?;
        let record = self
            .raw("verification", "findOne", |op| {
                Ok(op
                    .capture_table(EntityRole::Verification)?
                    .select_refs(|row| {
                        Ok(self
                            .verification_field(row, "value")?
                            .unwrap_or_default()
                            .strict_equals(&bound_value))
                    })?
                    .into_iter()
                    .next())
            })
            .await?;
        futures_util::future::OptionFuture::from(
            record.map(|record| self.output_verification(RecordSource::Live(record))),
        )
        .await
        .transpose()
    }
    async fn get_verification_by_identifier(
        &self,
        identifier: &str,
    ) -> AuthResult<Option<VerificationView>> {
        let bound_identifier = self.verification_query("identifier", identifier)?;
        let record = self
            .raw("verification", "findOne", |op| {
                Ok(op
                    .capture_table(EntityRole::Verification)?
                    .select_refs(|row| {
                        Ok(self
                            .verification_field(row, "identifier")?
                            .unwrap_or_default()
                            .strict_equals(&bound_identifier))
                    })?
                    .into_iter()
                    .next())
            })
            .await?;
        futures_util::future::OptionFuture::from(
            record.map(|record| self.output_verification(RecordSource::Live(record))),
        )
        .await
        .transpose()
    }

    async fn update_verification(
        &self,
        identifier: &str,
        update: VerificationUpdate,
    ) -> AuthResult<Option<VerificationView>> {
        self.update_verification_with_hooks(identifier, update)
            .await
    }
    async fn update_verification_by_identifier(
        &self,
        identifier: &str,
        value: Option<String>,
        expires_at: Option<DateTime<Utc>>,
    ) -> AuthResult<()> {
        let _ = self
            .update_verification(
                identifier,
                VerificationUpdate {
                    value: value.map(Into::into).unwrap_or_default(),
                    expires_at: expires_at.map(Into::into).unwrap_or_default(),
                    ..Default::default()
                },
            )
            .await?;
        Ok(())
    }
    async fn delete_verification_by_identifier(&self, identifier: &str) -> AuthResult<()> {
        let bound_identifier = self.verification_query("identifier", identifier)?;
        let _ = self
            .delete_verifications_with_hooks(
                |row| {
                    Ok(self
                        .verification_field(row, "identifier")?
                        .unwrap_or_default()
                        .strict_equals(&bound_identifier))
                },
                false,
            )
            .await?;
        Ok(())
    }
    async fn delete_verification(&self, id: &str) -> AuthResult<()> {
        let id = self.verification_query("id", id)?;
        let rows = self
            .raw("verification", "findOne", |op| {
                Ok(op
                    .capture_table(EntityRole::Verification)?
                    .select_refs(|row| Ok(row.field("id")?.unwrap_or_default().strict_equals(&id)))?
                    .into_iter()
                    .next()
                    .into_iter()
                    .collect())
            })
            .await?;
        let _ = self
            .finish_verification_delete(
                rows,
                |row| Ok(row.field("id")?.unwrap_or_default().strict_equals(&id)),
                false,
            )
            .await?;
        Ok(())
    }
    async fn delete_expired_verifications(&self) -> AuthResult<usize> {
        let now = self.verification_query("expiresAt", Value::Date(Utc::now().into()))?;
        self.delete_verifications_with_hooks(
            |row| {
                crate::memory_query::matches_all(["expiresAt"], |name| {
                    crate::memory_query::matches(
                        self.verification_field(row, name)?.as_ref(),
                        &now,
                        crate::WhereOperator::Lt,
                        crate::WhereMode::Sensitive,
                    )
                })
            },
            true,
        )
        .await
    }
    async fn consume_verification(
        &self,
        identifier: &str,
        value: &str,
    ) -> AuthResult<Option<VerificationView>> {
        let record = self
            .consume_verification_with_hooks(identifier, Some(value))
            .await?;
        match record {
            Some(record) if !record.expires_at.is_before(Utc::now())? => Ok(Some(record)),
            _ => Ok(None),
        }
    }
    async fn consume_verification_by_identifier(
        &self,
        identifier: &str,
    ) -> AuthResult<Option<VerificationView>> {
        let record = self
            .consume_verification_including_expired(identifier)
            .await?;
        match record {
            Some(record) if !record.expires_at.is_before(Utc::now())? => Ok(Some(record)),
            _ => Ok(None),
        }
    }
    async fn consume_verification_including_expired(
        &self,
        identifier: &str,
    ) -> AuthResult<Option<VerificationView>> {
        self.consume_verification_with_hooks(identifier, None).await
    }
}
