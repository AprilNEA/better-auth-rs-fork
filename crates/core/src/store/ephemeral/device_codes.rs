use super::rows::RowRef;
use super::table::TableRef;
use super::*;
use crate::store::schema::{EntityRole, resolve_field_name};

#[cfg(test)]
#[path = "device_claim_tests.rs"]
mod claim_tests;

#[derive(Clone)]
struct DeviceCodeOrigin {
    isolated: RowRef<FieldMap>,
    live: RowRef<FieldMap>,
    before: FieldMap,
}

#[derive(Default)]
pub(super) struct DeviceCodeTransaction {
    origins: Vec<DeviceCodeOrigin>,
    pub(super) consumed: Vec<DeviceCodeConsumption>,
}

impl DeviceCodeTransaction {
    pub(super) fn capture_origin(
        &mut self,
        live: RowRef<FieldMap>,
        isolated: RowRef<FieldMap>,
        before: FieldMap,
    ) {
        self.origins.push(DeviceCodeOrigin {
            isolated,
            live,
            before,
        });
    }
}

#[derive(Clone)]
pub(super) struct DeviceCodeConsumption {
    origin: Option<DeviceCodeOrigin>,
    binding_fields: [String; 5],
    selected_field: Option<String>,
    ownership_field: Option<String>,
}

impl DeviceCodeConsumption {
    pub(super) fn unchanged(&self, live: &TableRef<FieldMap>) -> AuthResult<bool> {
        let Some(origin) = &self.origin else {
            return Ok(true);
        };
        if !live.contains_ref(&origin.live)? {
            return Ok(false);
        }
        for name in self
            .binding_fields
            .iter()
            .chain(self.selected_field.iter())
            .chain(self.ownership_field.iter())
        {
            let same = match (origin.live.field(name)?, origin.before.get(name)) {
                (Some(actual), Some(before)) => actual.same_value_zero(before),
                (None, None) => true,
                _ => false,
            };
            if !same {
                return Ok(false);
            }
        }
        Ok(true)
    }
}

fn value<'a>(row: &'a FieldMap, name: &str) -> &'a Value {
    row.get(name).unwrap_or(&Value::Undefined)
}

impl EphemeralStore {
    fn device_column(&self, name: &str) -> String {
        let fields = self
            .model_fields
            .plugin_fields(EntityRole::DeviceCode)
            .adapter_fields(&[]);
        fields
            .fields()
            .get(name)
            .map_or(name, |field| {
                resolve_field_name(field.field_name.as_deref(), name)
            })
            .to_owned()
    }

    async fn find_device_code(
        &self,
        field: &str,
        operand: Value,
    ) -> AuthResult<Option<DeviceCode>> {
        let (column, operand) = self.plugin_query_field(EntityRole::DeviceCode, field, operand)?;
        let selected = self
            .raw("deviceCode", "findOne", |op| {
                Ok(op
                    .capture_table(EntityRole::DeviceCode)?
                    .select_refs(|row| {
                        Ok(crate::query::field_matches_equality(
                            &row.field(&column)?.unwrap_or_default(),
                            &operand,
                        ))
                    })?
                    .into_iter()
                    .next())
            })
            .await?;
        Ok(self
            .project_device_code_refs(selected.into_iter().collect())
            .await?
            .pop())
    }

    async fn project_device_code_refs(
        &self,
        sources: Vec<RowRef<FieldMap>>,
    ) -> AuthResult<Vec<DeviceCode>> {
        let bindings = sources
            .iter()
            .map(|source| {
                Ok(self
                    .model_fields
                    .device_code_storage_bindings(&source.shallow_fields()?))
            })
            .collect::<AuthResult<Vec<_>>>()?;
        let projected = self
            .project_plugin_refs(EntityRole::DeviceCode, sources)
            .await?;
        Ok(projected
            .into_iter()
            .zip(bindings)
            .map(|(fields, bindings)| DeviceCode::from(fields).with_storage_bindings(bindings))
            .collect())
    }

    async fn update_device_code_guarded(
        &self,
        id: &crate::SchemaValue<String>,
        status: &str,
        unclaimed: bool,
        input: FieldMap,
    ) -> AuthResult<bool> {
        let (id_column, id) =
            self.plugin_query_field(EntityRole::DeviceCode, "id", id.field_value())?;
        let status = self.plugin_query_value(EntityRole::DeviceCode, "status", status.into())?;
        let owner = if unclaimed {
            Some(self.plugin_query_value(EntityRole::DeviceCode, "userId", Value::Null)?)
        } else {
            None
        };
        let patch = self
            .prepare_plugin_fields(EntityRole::DeviceCode, input, false)
            .await?;
        if unclaimed {
            crate::store::validate_increment_one_update(false, !patch.is_empty())?;
        }
        let status_column = self.device_column("status");
        let owner_column = self.device_column("userId");
        let selected = self
            .raw(
                "deviceCode",
                if unclaimed { "incrementOne" } else { "update" },
                |op| {
                    let mut clauses =
                        vec![(id_column.as_str(), &id), (status_column.as_str(), &status)];
                    if let Some(owner) = &owner {
                        clauses.push((owner_column.as_str(), owner));
                    }
                    let selected = op
                        .capture_table(EntityRole::DeviceCode)?
                        .select_refs(|row| {
                            crate::memory_query::matches_all(clauses.iter(), |(name, expected)| {
                                Ok(crate::query::field_matches_equality(
                                    &row.field(name)?.unwrap_or_default(),
                                    expected,
                                ))
                            })
                        })?
                        .into_iter()
                        .next();
                    if let Some(source) = &selected {
                        source.apply_patch(patch)?;
                    }
                    Ok(selected)
                },
            )
            .await?;
        // Output callbacks run after a successful write, including boolean-returning writes.
        Ok(!self
            .project_device_code_refs(selected.into_iter().collect())
            .await?
            .is_empty())
    }
}

#[async_trait]
impl DeviceCodeStore for EphemeralStore {
    async fn create_device_code_record(&self, fields: FieldMap) -> AuthResult<Option<FieldMap>> {
        self.create_plugin_record(EntityRole::DeviceCode, fields, FieldMap::new())
            .await
            .map(Some)
    }

    async fn get_device_code_record(
        &self,
        id: &crate::SchemaValue<String>,
    ) -> AuthResult<Option<FieldMap>> {
        self.get_plugin_record(EntityRole::DeviceCode, id).await
    }

    async fn update_device_code_record(
        &self,
        id: &crate::SchemaValue<String>,
        fields: FieldMap,
    ) -> AuthResult<Option<FieldMap>> {
        self.update_plugin_record(EntityRole::DeviceCode, id, fields, FieldMap::new())
            .await
    }

    async fn create_device_code(&self, input: CreateDeviceCode) -> AuthResult<DeviceCode> {
        let source = self
            .create_plugin_ref(
                EntityRole::DeviceCode,
                input.into_adapter_fields()?,
                FieldMap::new(),
            )
            .await?;
        self.project_device_code_refs(vec![source])
            .await?
            .pop()
            .ok_or_else(|| AuthError::internal("Created device code was not projected"))
    }

    async fn get_device_code_by_device_code(
        &self,
        device_code: &str,
    ) -> AuthResult<Option<DeviceCode>> {
        self.find_device_code("deviceCode", device_code.into())
            .await
    }

    async fn get_device_code_by_user_code(
        &self,
        user_code: &str,
    ) -> AuthResult<Option<DeviceCode>> {
        self.find_device_code("userCode", user_code.into()).await
    }

    async fn update_device_code(
        &self,
        id: &crate::SchemaValue<String>,
        update: UpdateDeviceCode,
    ) -> AuthResult<DeviceCode> {
        let source = self
            .update_plugin_ref(
                EntityRole::DeviceCode,
                id,
                update.into_adapter_fields()?,
                FieldMap::new(),
            )
            .await?
            .ok_or_else(|| AuthError::not_found("Device code not found"))?;
        self.project_device_code_refs(vec![source])
            .await?
            .pop()
            .ok_or_else(|| AuthError::internal("Updated device code was not projected"))
    }

    async fn update_device_code_if_status(
        &self,
        id: &crate::SchemaValue<String>,
        current_status: &str,
        update: UpdateDeviceCode,
    ) -> AuthResult<bool> {
        self.update_device_code_guarded(id, current_status, false, update.into_adapter_fields()?)
            .await
    }

    async fn claim_device_code(
        &self,
        id: &crate::SchemaValue<String>,
        user_id: &crate::SchemaValue<String>,
    ) -> AuthResult<bool> {
        self.update_device_code_guarded(
            id,
            "pending",
            true,
            [("userId".into(), user_id.field_value())].into(),
        )
        .await
    }

    async fn consume_device_code(
        &self,
        expected: &DeviceCode,
        ownership: &crate::DeviceCodeOwnership,
    ) -> AuthResult<Option<DeviceCode>> {
        let (selected_column, selected_id) =
            self.plugin_query_field(EntityRole::DeviceCode, "id", expected.id.field_value())?;
        let mut query = ownership.query();
        crate::query::validate_where_operand(query.operator, &query.value)?;
        (query.field, query.value) =
            self.plugin_query_field(EntityRole::DeviceCode, &query.field, query.value)?;
        let approved =
            self.plugin_query_value(EntityRole::DeviceCode, "status", "approved".into())?;
        let (bindings, unchanged) = expected.consumption_bindings()?;
        let names = ["id", "deviceCode", "clientId", "userId", "status"];
        let columns = names.map(|name| self.device_column(name));
        let row = self
            .raw("deviceCode", "consumeOne", |op| {
                let table = op.capture_table(EntityRole::DeviceCode)?;
                let selected = table
                    .select_refs(|source| {
                        let selected = crate::query::field_matches_equality(
                            &source.field(&selected_column)?.unwrap_or_default(),
                            &selected_id,
                        );
                        if !selected {
                            return Ok(false);
                        }
                        let owns = crate::memory_query::matches_all([&query], |query| {
                            crate::memory_query::matches(
                                source.field(&query.field)?.as_ref(),
                                &query.value,
                                query.operator,
                                query.mode,
                            )
                        })?;
                        if !unchanged || !owns {
                            return Ok(false);
                        }
                        for (name, column) in names.iter().zip(&columns) {
                            if !source
                                .field(column)?
                                .unwrap_or_default()
                                .strict_equals(value(bindings, name))
                            {
                                return Ok(false);
                            }
                        }
                        Ok(!source.field(&columns[3])?.unwrap_or_default().is_null()
                            && !source
                                .field(&columns[3])?
                                .unwrap_or_default()
                                .is_undefined()
                            && crate::query::field_matches_equality(
                                &source.field(&columns[4])?.unwrap_or_default(),
                                &approved,
                            ))
                    })?
                    .into_iter()
                    .next();
                let Some(selected) = selected else {
                    return Ok(None);
                };
                op.replace_table(
                    EntityRole::DeviceCode,
                    table.without_refs(std::slice::from_ref(&selected))?,
                )?;
                if let Some(transaction) = &self.device_code_transaction {
                    let mut transaction = transaction.lock().map_err(|_| {
                        AuthError::internal("Ephemeral device consumption write set poisoned")
                    })?;
                    let origin = transaction
                        .origins
                        .iter()
                        .find(|origin| origin.isolated.same_row(&selected))
                        .cloned();
                    transaction.consumed.push(DeviceCodeConsumption {
                        origin,
                        selected_field: (selected_column != columns[0])
                            .then(|| selected_column.clone()),
                        binding_fields: columns,
                        ownership_field: (!matches!(
                            ownership,
                            crate::DeviceCodeOwnership::ClientId(_)
                        ))
                        .then(|| query.field.clone()),
                    });
                }
                Ok(Some(selected))
            })
            .await?;
        Ok(self
            .project_device_code_refs(row.into_iter().collect())
            .await?
            .pop())
    }

    async fn delete_device_code(&self, id: &crate::SchemaValue<String>) -> AuthResult<()> {
        self.delete_plugin_records(EntityRole::DeviceCode, id).await
    }

    async fn delete_device_code_if_status(
        &self,
        id: &crate::SchemaValue<String>,
        status: &str,
    ) -> AuthResult<bool> {
        let (id_column, id) =
            self.plugin_query_field(EntityRole::DeviceCode, "id", id.field_value())?;
        let status = self.plugin_query_value(EntityRole::DeviceCode, "status", status.into())?;
        let column = self.device_column("status");
        self.raw("deviceCode", "delete", |op| {
            let table = op.capture_table(EntityRole::DeviceCode)?;
            let selected = table.select_refs(|row| {
                crate::memory_query::matches_all(
                    [(id_column.as_str(), &id), (column.as_str(), &status)],
                    |(name, expected)| {
                        Ok(crate::query::field_matches_equality(
                            &row.field(name)?.unwrap_or_default(),
                            expected,
                        ))
                    },
                )
            })?;
            op.replace_table(EntityRole::DeviceCode, table.without_refs(&selected)?)?;
            Ok(!selected.is_empty())
        })
        .await
    }
}

#[async_trait]
impl DeviceCodeStore for super::transactions::EphemeralTransaction {
    async fn create_device_code_record(&self, fields: FieldMap) -> AuthResult<Option<FieldMap>> {
        self.store.create_device_code_record(fields).await
    }
    async fn get_device_code_record(
        &self,
        id: &crate::SchemaValue<String>,
    ) -> AuthResult<Option<FieldMap>> {
        self.store.get_device_code_record(id).await
    }
    async fn update_device_code_record(
        &self,
        id: &crate::SchemaValue<String>,
        fields: FieldMap,
    ) -> AuthResult<Option<FieldMap>> {
        self.store.update_device_code_record(id, fields).await
    }

    async fn create_device_code(&self, input: CreateDeviceCode) -> AuthResult<DeviceCode> {
        self.store.create_device_code(input).await
    }
    async fn get_device_code_by_device_code(
        &self,
        device_code: &str,
    ) -> AuthResult<Option<DeviceCode>> {
        self.store.get_device_code_by_device_code(device_code).await
    }
    async fn get_device_code_by_user_code(
        &self,
        user_code: &str,
    ) -> AuthResult<Option<DeviceCode>> {
        self.store.get_device_code_by_user_code(user_code).await
    }
    async fn update_device_code(
        &self,
        id: &crate::SchemaValue<String>,
        update: UpdateDeviceCode,
    ) -> AuthResult<DeviceCode> {
        self.store.update_device_code(id, update).await
    }
    async fn update_device_code_if_status(
        &self,
        id: &crate::SchemaValue<String>,
        current_status: &str,
        update: UpdateDeviceCode,
    ) -> AuthResult<bool> {
        self.store
            .update_device_code_if_status(id, current_status, update)
            .await
    }
    async fn claim_device_code(
        &self,
        id: &crate::SchemaValue<String>,
        user_id: &crate::SchemaValue<String>,
    ) -> AuthResult<bool> {
        self.store.claim_device_code(id, user_id).await
    }
    async fn consume_device_code(
        &self,
        expected: &DeviceCode,
        ownership: &crate::DeviceCodeOwnership,
    ) -> AuthResult<Option<DeviceCode>> {
        self.store.consume_device_code(expected, ownership).await
    }
    async fn delete_device_code(&self, id: &crate::SchemaValue<String>) -> AuthResult<()> {
        self.store.delete_device_code(id).await
    }
    async fn delete_device_code_if_status(
        &self,
        id: &crate::SchemaValue<String>,
        status: &str,
    ) -> AuthResult<bool> {
        self.store.delete_device_code_if_status(id, status).await
    }
}
