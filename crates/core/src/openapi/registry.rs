use indexmap::IndexMap;
use serde_json::{Map, Value};

use crate::plugin_runtime::ModelFields as RegisteredFields;
use crate::{AuthConfig, AuthResult, HttpMethod, user_fields::UserConfig};

use super::{
    OpenApiBuilder, OpenApiPluginMetadata, OpenApiRouteMetadata, OpenApiSpec,
    catalog::{Endpoint, catalog},
    metadata::{ModelFields, model_projection, project_field, property_key_order},
};

struct Route {
    plugin: Option<String>,
    path: String,
    methods: Vec<HttpMethod>,
    metadata: OpenApiRouteMetadata,
}

/// Immutable documentation for a configured authentication instance.
/// Request-specific base URLs are supplied when the document is generated.
pub struct OpenApiRegistry {
    models: IndexMap<String, ModelFields>,
    input_properties: Map<String, Value>,
    input_required: Vec<String>,
    routes: Vec<Route>,
}

impl OpenApiRegistry {
    /// Build documentation from configured metadata and policies returned by `ModelFields::resolve`.
    /// Final registered policies replace explicit metadata through the shared field projection.
    pub fn new(
        adapter_config: &AuthConfig,
        endpoint_user_fields: &UserConfig,
        plugins: impl IntoIterator<Item = OpenApiPluginMetadata>,
        secondary_storage: bool,
        registered_fields: &RegisteredFields,
    ) -> AuthResult<Self> {
        let catalog = catalog()?;
        let plugins: Vec<_> = plugins.into_iter().collect();
        let mut input_fields: ModelFields = endpoint_user_fields
            .fields()
            .iter()
            .map(|(key, field)| Ok((key.clone(), project_field(key, field, true)?)))
            .collect::<AuthResult<_>>()?;
        let mut routes = Vec::new();
        let disabled = &adapter_config.disabled_paths;
        for endpoint in catalog.endpoints(None) {
            if let Some(route) = prepare_route(endpoint, None, disabled)? {
                routes.push(route);
            }
        }
        for plugin in &plugins {
            if let Some(fields) = plugin.models.get("user") {
                for (name, field) in fields {
                    if !endpoint_user_fields.fields().contains_key(name) {
                        let _ = input_fields.insert(name.clone(), field.clone());
                    }
                }
            }
            if plugin.id == "open-api" {
                continue;
            }
            for endpoint in &plugin.endpoints {
                // Core endpoint keys are documented by the unconditional core catalog.
                if catalog
                    .endpoints(None)
                    .iter()
                    .any(|core| core.key == endpoint.key)
                {
                    continue;
                }
                if let Some(route) = prepare_route(endpoint, Some(&plugin.id), disabled)? {
                    routes.push(route);
                }
            }
        }
        let models = super::models::model_fields(
            adapter_config,
            &plugins,
            registered_fields,
            secondary_storage,
        )?;
        input_fields
            .sort_by(|left, _, right, _| property_key_order(left).cmp(&property_key_order(right)));
        let input_properties = input_fields
            .iter()
            .filter_map(|(key, field)| {
                field
                    .input_property
                    .clone()
                    .map(|property| (key.clone(), property))
            })
            .collect();
        let input_required = input_fields
            .iter()
            .filter(|(_, field)| field.input_property.is_some() && field.input_required)
            .map(|(key, _)| key.clone())
            .collect();
        Ok(Self {
            models,
            input_properties,
            input_required,
            routes,
        })
    }

    pub fn generate(&self, base_url: &str) -> OpenApiSpec {
        let mut builder = OpenApiBuilder::new("Better Auth", "1.1.0")
            .description("API Reference for your Better Auth Instance")
            .base_url(base_url)
            .user_input_properties(self.input_properties.clone(), self.input_required.clone());
        for (name, fields) in &self.models {
            let (properties, required) = model_projection(fields);
            builder = builder.model_properties(name, properties, required);
        }
        for route in &self.routes {
            for method in &route.methods {
                builder = builder.documented_route(
                    method,
                    &route.path,
                    route.plugin.as_deref(),
                    &route.metadata,
                );
            }
        }
        builder.build()
    }
}

fn prepare_route(
    endpoint: &Endpoint,
    plugin: Option<&str>,
    disabled: &[String],
) -> AuthResult<Option<Route>> {
    let Some(path) = endpoint.path.as_deref() else {
        return Ok(None);
    };
    if endpoint.metadata.server_only || disabled.iter().any(|disabled| disabled == path) {
        return Ok(None);
    }
    Ok(Some(Route {
        plugin: plugin.map(str::to_owned),
        path: path.to_owned(),
        methods: endpoint.methods()?,
        metadata: endpoint.metadata.clone(),
    }))
}
