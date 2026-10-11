use indexmap::{IndexMap, IndexSet};

use crate::{
    AuthConfig, AuthResult, FieldMap, plugin_runtime::ModelFields, user_fields::UserConfig,
};

use super::{
    OpenApiPluginMetadata,
    metadata::{ModelFields as DocumentationFields, project_field},
};

fn core_declarations(config: &AuthConfig) -> IndexMap<String, UserConfig> {
    [
        ("user", config.user.user_field_schema()),
        (
            "session",
            crate::store::session_field_schema(&config.session, &FieldMap::new()),
        ),
        ("account", config.account.field_schema()),
        ("verification", config.verification.field_schema()),
    ]
    .into_iter()
    .map(|(name, fields)| (name.to_owned(), fields))
    .collect()
}

fn field_order(
    fields: &UserConfig,
    metadata: &DocumentationFields,
    order: &IndexSet<String>,
) -> IndexSet<String> {
    let mut registered = fields
        .fields()
        .keys()
        .filter(|name| !metadata.contains_key(*name));
    // Explicit metadata keeps its insertion slots. Final declarations order the remaining fields after complete model replacements.
    order
        .iter()
        .filter_map(|name| {
            if metadata.contains_key(name) {
                Some(name.clone())
            } else if fields.fields().contains_key(name) {
                registered.next().cloned()
            } else {
                None
            }
        })
        .collect()
}

pub(super) fn model_fields(
    config: &AuthConfig,
    plugins: &[OpenApiPluginMetadata],
    registered: &ModelFields,
    secondary_storage: bool,
) -> AuthResult<IndexMap<String, DocumentationFields>> {
    let mut policies = core_declarations(config);
    for (name, fields) in registered.declared_models()? {
        let _ = policies.entry(name).or_insert(fields);
    }
    let mut models: IndexMap<String, DocumentationFields> = IndexMap::new();
    let mut order: IndexMap<String, IndexSet<String>> = IndexMap::new();
    // Documentation always includes Session. Runtime persistence selection remains independent.
    for (name, fields) in core_declarations(&AuthConfig::default()) {
        let _ = order.insert(name.clone(), fields.fields().keys().cloned().collect());
        let _ = models.insert(name, DocumentationFields::new());
    }
    for plugin in plugins {
        for (name, fields) in &plugin.models {
            order
                .entry(name.clone())
                .or_default()
                .extend(fields.keys().cloned());
            models
                .entry(name.clone())
                .or_default()
                .extend(fields.clone());
        }
        for (name, fields) in &plugin.registered_field_names {
            let _ = models.entry(name.clone()).or_default();
            order
                .entry(name.clone())
                .or_default()
                .extend(fields.iter().cloned());
        }
    }
    for (name, fields) in policies {
        let positions = order.entry(name.clone()).or_default();
        positions.extend(fields.fields().keys().cloned());
        let model = models.entry(name.clone()).or_default();
        let positions = field_order(&fields, model, positions);
        model.extend(
            fields
                .fields()
                .iter()
                .map(|(key, field)| Ok((key.clone(), project_field(key, field, name == "user")?)))
                .collect::<AuthResult<DocumentationFields>>()?,
        );
        model.sort_by(|left, _, right, _| {
            positions
                .get_index_of(left)
                .cmp(&positions.get_index_of(right))
        });
    }
    if secondary_storage && !config.verification.store_in_database {
        let _ = models.shift_remove("verification");
    }
    Ok(models)
}
