//! Collect complete plugin declarations before adapter and runtime initialization.

use super::ModelFields;
use crate::{AuthResult, store::schema::EntityRole, user_fields::UserConfig};

impl ModelFields {
    /// Register user schema fields in plugin registration order.
    pub fn register_user_fields(&mut self, fields: UserConfig) {
        self.extend(EntityRole::User, fields);
    }

    /// Register one plugin's native User declarations at its schema position.
    #[doc(hidden)]
    pub fn register_native_user_fields(&mut self, enabled_metadata: &str) {
        let metadata = [(enabled_metadata.to_owned(), serde_json::Value::Bool(true))].into();
        let names: Vec<_> = crate::wire::UserView::active_plugin_fields(&metadata).collect();
        self.set_plugin_metadata(&metadata);
        let mut fields = UserConfig::default().user_field_schema_with_plugins(&names);
        fields
            .fields_mut()
            .retain(|name, _| names.contains(&name.as_str()));
        self.register_user_fields(fields);
    }

    /// Register one plugin's native Session declarations at its schema position.
    #[doc(hidden)]
    pub fn register_native_session_fields(&mut self, enabled_metadata: &str) -> AuthResult<()> {
        let metadata = [(enabled_metadata.to_owned(), serde_json::Value::Bool(true))].into();
        self.set_plugin_metadata(&metadata);
        let fields = UserConfig {
            additional_fields: Some(
                crate::wire::SessionView::active_plugin_fields(&metadata)
                    .map(|name| {
                        (
                            name.to_owned(),
                            crate::user_fields::UserFieldConfig {
                                required: Some(false),
                                input: Some(false),
                                ..Default::default()
                            },
                        )
                    })
                    .collect(),
            ),
        };
        self.register_model_fields(EntityRole::Session, fields)
    }

    /// Merge complete adapter field declarations for a native model in registration order.
    /// Reset any preceding name override to the adapter's native table-name mapping.
    pub fn register_model_fields(
        &mut self,
        role: EntityRole,
        fields: UserConfig,
    ) -> AuthResult<()> {
        self.register(role, fields);
        Ok(())
    }

    /// Merge a native model declaration at its first schema position.
    /// Omitted or empty names reset the declared name to the logical model name.
    /// Field-only registration resets name overrides to the adapter's native table-name mapping.
    /// Storage adapters retain responsibility for the physical model and migrations.
    pub fn register_model_schema(
        &mut self,
        role: EntityRole,
        model_name: Option<&str>,
        fields: UserConfig,
    ) -> AuthResult<()> {
        self.register_model_fields(role, fields)?;
        self.set_model_name(role, model_name)
    }

    /// Take one plugin's successful declarations, including empty models and ordered field names.
    #[doc(hidden)]
    pub fn take_registered_model_field_names(&mut self) -> AuthResult<Vec<(String, Vec<String>)>> {
        self.take_registered_declarations()
    }
}
