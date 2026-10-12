use async_trait::async_trait;
use chrono::Utc;

use super::{EphemeralStore, rows::RowRef};
use crate::store::{PasskeyStore, schema::EntityRole};
use crate::{
    AuthError, AuthResult, CreatePasskey, FieldMap, FieldValue, FromFieldMap, Passkey, SchemaValue,
    UpdatePasskey, UpdatePasskeyAuthentication,
};

impl EphemeralStore {
    async fn project_passkey_refs(&self, rows: Vec<RowRef<FieldMap>>) -> AuthResult<Vec<Passkey>> {
        let schema = self.model_fields.plugin_fields(EntityRole::Passkey);
        self.project_plugin_refs(EntityRole::Passkey, rows.clone())
            .await?
            .into_iter()
            .zip(rows)
            .map(|(mut fields, source)| {
                let order = fields.keys().cloned().collect();
                for name in ["credential", "updatedAt"] {
                    if !schema.fields().contains_key(name)
                        && let Some(value) = source.field(name)?
                    {
                        let _ = fields.insert(name.into(), value);
                    }
                }
                let mut passkey = Passkey::from_field_values(fields)?;
                passkey.field_order = order;
                Ok(passkey)
            })
            .collect()
    }

    fn passkey_private_fields(
        &self,
        input: &FieldMap,
        updated_at: Option<crate::FieldDate>,
    ) -> AuthResult<FieldMap> {
        let schema = self.model_fields.plugin_fields(EntityRole::Passkey);
        let mut private = FieldMap::new();
        for name in ["credential", "updatedAt"] {
            if !schema.fields().contains_key(name)
                && !schema.owns_adapter_column(&name.to_owned(), |key| Ok(key.to_owned()))?
            {
                let value = input.get(name).cloned().or_else(|| {
                    if name == "updatedAt" {
                        updated_at.clone().map(Into::into)
                    } else {
                        None
                    }
                });
                if let Some(value) = value {
                    let _ = private.insert(name.into(), value);
                }
            }
        }
        Ok(private)
    }

    async fn find_passkey(
        &self,
        predicate: impl Fn(&FieldMap) -> bool + Send,
    ) -> AuthResult<Option<Passkey>> {
        let selected = self
            .raw("passkey", "findOne", move |op| {
                Ok(op
                    .capture_table(EntityRole::Passkey)?
                    .select_refs(|row| Ok(predicate(&row.shallow_fields()?)))?
                    .into_iter()
                    .next())
            })
            .await?;
        Ok(self
            .project_passkey_refs(selected.into_iter().collect())
            .await?
            .pop())
    }
}

#[async_trait]
impl PasskeyStore for EphemeralStore {
    async fn create_passkey_record(&self, input: FieldMap) -> AuthResult<Option<FieldMap>> {
        self.create_plugin_record(EntityRole::Passkey, input, Default::default())
            .await
            .map(Some)
    }

    async fn get_passkey_record(&self, id: &SchemaValue<String>) -> AuthResult<Option<FieldMap>> {
        self.get_plugin_record(EntityRole::Passkey, id).await
    }

    async fn update_passkey_record(
        &self,
        id: &SchemaValue<String>,
        input: FieldMap,
    ) -> AuthResult<Option<FieldMap>> {
        self.update_plugin_record(EntityRole::Passkey, id, input, Default::default())
            .await
    }

    async fn create_passkey(&self, input: CreatePasskey) -> AuthResult<Passkey> {
        self.create_passkey_optional(input)
            .await?
            .ok_or_else(|| AuthError::internal("Passkey creation returned no record"))
    }

    async fn create_passkey_optional(&self, input: CreatePasskey) -> AuthResult<Option<Passkey>> {
        let mut fields = input.into_adapter_fields()?;
        let now: crate::FieldDate = Utc::now().into();
        let _ = fields.insert("createdAt".into(), now.clone().into());
        let private = self.passkey_private_fields(&fields, Some(now))?;
        let source = self
            .create_plugin_ref(EntityRole::Passkey, fields, private)
            .await?;
        Ok(self.project_passkey_refs(vec![source]).await?.pop())
    }

    async fn get_passkey_by_id(&self, id: &str) -> AuthResult<Option<Passkey>> {
        let (column, id) = self.plugin_query_field(EntityRole::Passkey, "id", id.into())?;
        self.find_passkey(|row| {
            row.get(&column)
                .is_some_and(|value| value.strict_equals(&id))
        })
        .await
    }

    async fn get_passkey_by_credential_id_value(
        &self,
        credential_id: &FieldValue,
    ) -> AuthResult<Option<Passkey>> {
        let schema = self.model_fields.plugin_fields(EntityRole::Passkey);
        let column = schema.record_storage_key("credentialID");
        let value =
            self.plugin_query_value(EntityRole::Passkey, "credentialID", credential_id.clone())?;
        self.find_passkey(|row| {
            crate::query::field_matches_equality(
                row.get(column).unwrap_or(&FieldValue::Undefined),
                &value,
            )
        })
        .await
    }

    async fn list_passkeys_by_user_value(&self, user_id: &FieldValue) -> AuthResult<Vec<Passkey>> {
        let schema = self.model_fields.plugin_fields(EntityRole::Passkey);
        let column = schema.record_storage_key("userId");
        let value = self.plugin_query_value(EntityRole::Passkey, "userId", user_id.clone())?;
        let selected = self
            .raw("passkey", "findMany", |op| {
                Ok(crate::query::paginate_memory(
                    op.capture_table(EntityRole::Passkey)?.select_refs(|row| {
                        Ok(crate::query::field_matches_equality(
                            &row.field(column)?.unwrap_or_default(),
                            &value,
                        ))
                    })?,
                    Some(self.config.advanced.database.find_many_limit()),
                    None,
                ))
            })
            .await?;
        self.project_passkey_refs(selected).await
    }

    async fn update_passkey_authentication_optional(
        &self,
        id: &SchemaValue<String>,
        update: UpdatePasskeyAuthentication,
    ) -> AuthResult<Option<Passkey>> {
        let mut fields = FieldMap::new();
        let updated_at = match update {
            UpdatePasskeyAuthentication::Native { counter } => {
                let _ = fields.insert("counter".into(), FieldValue::from(counter));
                None
            }
            UpdatePasskeyAuthentication::Legacy {
                credential,
                counter,
                backed_up,
                device_type,
            } => {
                fields.extend([
                    ("counter".into(), FieldValue::from(counter)),
                    ("backedUp".into(), backed_up.into()),
                    ("deviceType".into(), device_type.into()),
                ]);
                let _ = fields.insert("credential".into(), credential.into());
                Some(Utc::now().into())
            }
        };
        let private = self.passkey_private_fields(&fields, updated_at)?;
        let selected = self
            .update_plugin_ref(EntityRole::Passkey, id, fields, private)
            .await?;
        Ok(self
            .project_passkey_refs(selected.into_iter().collect())
            .await?
            .pop())
    }

    async fn update_passkey_optional(
        &self,
        id: &SchemaValue<String>,
        update: UpdatePasskey,
    ) -> AuthResult<Option<Passkey>> {
        let fields = update.into_adapter_fields()?;
        let private = self.passkey_private_fields(&fields, Some(Utc::now().into()))?;
        let selected = self
            .update_plugin_ref(EntityRole::Passkey, id, fields, private)
            .await?;
        Ok(self
            .project_passkey_refs(selected.into_iter().collect())
            .await?
            .pop())
    }

    async fn delete_passkey(&self, id: &str) -> AuthResult<()> {
        self.delete_plugin_records(EntityRole::Passkey, &id.into())
            .await
    }
}
