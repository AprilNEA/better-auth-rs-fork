use super::*;

impl ModelFields {
    /// Capture original physical bindings under their logical names before output policies run.
    #[doc(hidden)]
    pub fn device_code_storage_bindings(&self, stored: &FieldMap) -> FieldMap {
        let schema = self
            .plugin_fields(EntityRole::DeviceCode)
            .adapter_fields(&[]);
        ["id", "deviceCode", "clientId", "userId", "status"]
            .into_iter()
            .map(|name| {
                let physical = schema.fields().get(name).map_or(name, |field| {
                    resolve_field_name(field.field_name.as_deref(), name)
                });
                (
                    name.to_owned(),
                    stored.get(physical).cloned().unwrap_or_default(),
                )
            })
            .collect()
    }
}
