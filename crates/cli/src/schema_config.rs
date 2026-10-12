pub(crate) use better_auth_schema_registry::FieldReferenceAction as OnDelete;
use better_auth_schema_registry::{canonical_field_name, resolve_field_name};
use std::collections::{BTreeMap, BTreeSet};

use better_auth_schema_registry::{EntityRole, ExtraEntitySchema, FieldDef};
use heck::{ToLowerCamelCase, ToSnakeCase};
use serde::Deserialize;

#[cfg(test)]
mod empty_field_name_tests;
#[cfg(test)]
mod empty_model_name_tests;
#[cfg(test)]
mod json_storage_tests;
#[cfg(test)]
mod native_empty_field_mapping_tests;
#[cfg(test)]
mod plugin_display_field_tests;
#[cfg(test)]
mod plugin_record_policy_tests;
#[cfg(test)]
mod shared_column_tests;
#[cfg(test)]
mod shared_declaration_tests;
#[cfg(test)]
mod two_factor_policy_tests;

#[derive(Clone, Copy, Default, PartialEq, Eq, clap::ValueEnum)]
pub(crate) enum IdGeneration {
    #[default]
    Random,
    Serial,
    Uuid,
    Database,
}

#[derive(Clone, Copy, Default, PartialEq, Eq, clap::ValueEnum)]
pub(crate) enum Database {
    #[default]
    Sqlite,
    Postgres,
    Mysql,
}

pub(crate) fn core_field(role: Option<EntityRole>, column: &str) -> Option<&'static FieldDef> {
    better_auth_schema_registry::core_fields(role?)
        .iter()
        .find(|field| field.column_name.unwrap_or(field.name) == column)
}

impl IdGeneration {
    pub(crate) fn rust_type(self, database: Database) -> &'static str {
        match (self, database) {
            (Self::Serial, Database::Sqlite) => "i64",
            (Self::Serial, _) => "i32",
            (Self::Uuid, Database::Postgres) => "Uuid",
            _ => "String",
        }
    }
}

#[derive(Default, Deserialize)]
#[serde(transparent)]
pub(crate) struct SchemaConfig(pub BTreeMap<String, ModelConfig>);

#[derive(Clone, Copy, Default)]
pub(crate) struct SchemaOptions {
    pub session_active_column: bool,
    pub api_key_legacy_schema: bool,
    pub device_code_legacy_schema: bool,
    pub passkey_legacy_schema: bool,
    pub two_factor_legacy_schema: bool,
    pub organization_legacy_schema: bool,
}

#[derive(Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct ModelConfig {
    pub model_name: Option<String>,
    pub fields: Option<BTreeMap<String, String>>,
    #[serde(default)]
    pub additional_fields: indexmap::IndexMap<String, AdditionalField>,
}

#[derive(Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct AdditionalField {
    #[serde(rename = "type")]
    pub field_type: FieldType,
    pub field_name: Option<String>,
    pub required: Option<bool>,
    #[serde(default)]
    pub unique: bool,
    #[serde(default)]
    pub index: bool,
    #[serde(default)]
    pub bigint: bool,
    #[serde(default)]
    pub sortable: bool,
    pub references: Option<Reference>,
}

#[derive(Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Reference {
    pub model: String,
    pub field: String,
    pub on_delete: Option<OnDelete>,
}

impl AdditionalField {
    fn storage_type(&self, database: Database) -> Result<&'static str, String> {
        if database == Database::Sqlite
            && matches!(&self.field_type, FieldType::Name(name) if name == "json")
            && self.references.is_none()
        {
            Ok("better_auth::seaorm::SqlText")
        } else {
            self.rust_type()
        }
    }

    fn rust_type(&self) -> Result<&'static str, String> {
        let field_type = self.field_type.rust_type()?;
        Ok(
            if self
                .references
                .as_ref()
                .is_some_and(|reference| reference.field == "id")
            {
                // The migration uses the ID storage type even when the public field is a number.
                "better_auth::seaorm::ReferenceId"
            } else {
                field_type
            },
        )
    }
}

#[derive(Clone, Deserialize)]
#[serde(untagged)]
pub(crate) enum FieldType {
    Name(String),
    Enum(Vec<String>),
}

impl FieldType {
    fn rust_type(&self) -> Result<&'static str, String> {
        match self {
            Self::Name(name) => match name.as_str() {
                "string" => Ok("String"),
                "number" => Ok("better_auth::seaorm::SqlNumber"),
                "boolean" => Ok("bool"),
                "date" => Ok("DateTimeUtc"),
                "json" => Ok("Json"),
                "string[]" => Ok("StringArray"),
                "number[]" => Ok("NumberArray"),
                _ => Err(format!("unsupported additional field type `{name}`")),
            },
            Self::Enum(values) => {
                if values.is_empty() {
                    return Err("an enum field must contain at least one string".to_owned());
                }
                Ok("String")
            }
        }
    }
}

pub(crate) struct Entity {
    pub module: syn::Ident,
    pub name: &'static str,
    pub registry_table: &'static str,
    pub table: String,
    pub role: Option<EntityRole>,
    pub native_catalog: bool,
    pub fields: Vec<Field>,
    registry_columns: BTreeMap<&'static str, String>,
    logical_columns: BTreeMap<String, String>,
    pub session_row_presence: bool,
    pub api_key_native_schema: bool,
    pub device_code_native_schema: bool,
    pub passkey_native_schema: bool,
    pub two_factor_native_schema: bool,
}

pub(crate) struct Field {
    pub ident: syn::Ident,
    pub aliases: Vec<String>,
    pub logical_name: String,
    pub ty: syn::Type,
    pub column: String,
    pub registry_column: Option<&'static str>,
    pub serialized: Option<String>,
    pub primary_key: bool,
    pub reference_override: Option<bool>,
    pub unique: Option<bool>,
    pub attributes: Option<AdditionalField>,
}

impl SchemaConfig {
    pub(crate) fn validate(&self) -> Result<(), String> {
        for name in self.0.keys() {
            if !matches!(
                name.as_str(),
                "user"
                    | "account"
                    | "verification"
                    | "apikey"
                    | "deviceCode"
                    | "passkey"
                    | "twoFactor"
                    | "jwks"
                    | "walletAddress"
                    | "rateLimit"
                    | "session"
                    | "organization"
                    | "member"
                    | "invitation"
                    | "team"
                    | "teamMember"
                    | "organizationRole"
            ) {
                return Err(format!("unknown schema model `{name}`"));
            }
        }
        Ok(())
    }
}

impl Entity {
    pub(crate) fn resolve_ids(
        &mut self,
        generation: IdGeneration,
        database: Database,
    ) -> Result<(), String> {
        for field in &mut self.fields {
            let reference = field.references_id(self.registry_table);
            if !field.primary_key && !reference {
                continue;
            }
            let kind = if reference
                && field.attributes.is_some()
                && generation.rust_type(database) == "String"
            {
                "better_auth::seaorm::ReferenceId"
            } else {
                generation.rust_type(database)
            };
            let optional = matches!(&field.ty, syn::Type::Path(path) if path.path.segments.last().is_some_and(|segment| segment.ident == "Option"));
            field.ty = syn::parse_str(&if optional {
                format!("Option<{kind}>")
            } else {
                kind.to_owned()
            })
            .map_err(|error| format!("invalid ID type: {error}"))?;
        }
        Ok(())
    }

    pub(crate) fn resolve(
        definition: &ExtraEntitySchema,
        fields: &[FieldDef],
        config: Option<&ModelConfig>,
        database: Database,
        options: SchemaOptions,
    ) -> Result<Self, String> {
        let session_row_presence =
            definition.role == Some(EntityRole::Session) && !options.session_active_column;
        let api_key_native_schema =
            definition.role == Some(EntityRole::ApiKey) && !options.api_key_legacy_schema;
        let device_code_native_schema =
            definition.role == Some(EntityRole::DeviceCode) && !options.device_code_legacy_schema;
        let passkey_native_schema =
            definition.role == Some(EntityRole::Passkey) && !options.passkey_legacy_schema;
        let two_factor_native_schema = !options.two_factor_legacy_schema
            && (definition.role == Some(EntityRole::TwoFactor)
                || definition.role == Some(EntityRole::User)
                    && fields
                        .iter()
                        .any(|field| field.name == "two_factor_enabled"));
        let native_catalog = match definition.role {
            Some(EntityRole::Session) => session_row_presence,
            Some(EntityRole::ApiKey) => api_key_native_schema,
            Some(EntityRole::DeviceCode) => device_code_native_schema,
            Some(EntityRole::Passkey) => passkey_native_schema,
            Some(EntityRole::TwoFactor) => two_factor_native_schema,
            Some(EntityRole::Organization) => !options.organization_legacy_schema,
            Some(_) => true,
            None => false,
        };
        let mut fields = fields
            .iter()
            .filter(|field| !(native_catalog && field.adapter_private.is_some()))
            .collect::<Vec<_>>();
        if native_catalog && definition.role == Some(EntityRole::Organization) {
            fields.sort_by_key(|field| field.name == "metadata");
        }
        if api_key_native_schema {
            fields.sort_by_key(|field| match field.name {
                "id" => 0,
                "config_id" => 1,
                "name" => 2,
                "start" => 3,
                "reference_id" => 4,
                "prefix" => 5,
                "key_hash" => 6,
                _ => 7,
            });
        }
        if passkey_native_schema {
            fields.sort_by_key(|field| match field.name {
                "created_at" => 1,
                "aaguid" => 2,
                _ => 0,
            });
        }
        let mut entity = Self {
            module: syn::parse_str(definition.mod_name)
                .map_err(|error| format!("invalid model name: {error}"))?,
            name: definition.mod_name,
            registry_table: definition.table_name,
            table: if native_catalog {
                model_name(definition.mod_name)
            } else {
                definition.table_name.to_owned()
            },
            role: definition.role,
            native_catalog,
            session_row_presence,
            api_key_native_schema,
            device_code_native_schema,
            passkey_native_schema,
            two_factor_native_schema,
            registry_columns: BTreeMap::new(),
            logical_columns: BTreeMap::new(),
            fields: fields
                .iter()
                .map(|field| {
                    let logical_name = definition.role.map_or_else(
                        || field.name.to_lower_camel_case(),
                        |role| canonical_field_name(role, field.name),
                    );
                    Ok(Field {
                        aliases: vec![field.name.to_owned(), logical_name.clone()],
                        ident: syn::parse_str(field.name)
                            .map_err(|error| format!("invalid field name: {error}"))?,
                        ty: syn::parse_str(if api_key_native_schema && field.ty == "Option<f64>" {
                            "Option<better_auth::seaorm::SqlNumber>"
                        } else if api_key_native_schema && field.ty == "bool" {
                            "Option<bool>"
                        } else if passkey_native_schema && field.name == "created_at" {
                            "Option<DateTimeUtc>"
                        } else if two_factor_native_schema
                            && matches!(field.name, "verified" | "two_factor_enabled")
                        {
                            "Option<bool>"
                        } else if two_factor_native_schema
                            && field.name == "failed_verification_count"
                        {
                            if database == Database::Sqlite {
                                "Option<i64>"
                            } else {
                                "Option<i32>"
                            }
                        } else if passkey_native_schema
                            && field.name == "counter"
                            && database != Database::Sqlite
                        {
                            "i32"
                        } else if definition.role == Some(EntityRole::Invitation)
                            && field.name == "role"
                        {
                            "Option<String>"
                        } else if database != Database::Sqlite
                            && matches!(
                                (definition.role, field.name),
                                (Some(EntityRole::Team), "member_count")
                                    | (Some(EntityRole::WalletAddress), "chain_id")
                            )
                        {
                            "i32"
                        } else if database != Database::Sqlite
                            && definition.role == Some(EntityRole::OrganizationRole)
                            && field.name == "permission"
                        {
                            "String"
                        } else {
                            field.ty
                        })
                        .map_err(|error| format!("invalid field type: {error}"))?,
                        column: if native_catalog
                            && (session_row_presence
                                || core_field(
                                    definition.role,
                                    field.column_name.unwrap_or(field.name),
                                )
                                .is_some()
                                || two_factor_native_schema && field.name == "two_factor_enabled")
                        {
                            logical_name.clone()
                        } else {
                            field.column_name.unwrap_or(field.name).to_owned()
                        },
                        logical_name,
                        registry_column: Some(field.column_name.unwrap_or(field.name)),
                        serialized: (definition.mod_name == "user"
                            && matches!(
                                field.name,
                                "username" | "display_username" | "last_login_method"
                            ))
                        .then(|| field.name.to_lower_camel_case()),
                        primary_key: field.is_primary_key,
                        reference_override: (device_code_native_schema && field.name == "user_id")
                            .then_some(false),
                        unique: None,
                        attributes: None,
                    })
                })
                .collect::<Result<_, String>>()?,
        };
        if let Some(config) = config {
            if let Some(table) = config.model_name.as_ref().filter(|name| !name.is_empty()) {
                entity.table.clone_from(table);
            }
            for (name, column) in config.fields.iter().flatten() {
                let field = entity
                    .fields
                    .iter_mut()
                    .find(|field| {
                        !field.primary_key
                            && (field.ident.to_string().to_lower_camel_case() == *name
                                || (entity.name == "api_key"
                                    && name == "key"
                                    && field.ident == "key_hash")
                                || (entity.name == "passkey"
                                    && name == "credentialID"
                                    && field.ident == "credential_id"))
                    })
                    .ok_or_else(|| {
                        format!("unknown configurable field `{}.{name}`", entity.name)
                    })?;
                if column.is_empty() {
                    continue;
                }
                field.column.clone_from(column);
                if field.serialized.is_some() {
                    field.serialized = Some(column.clone());
                }
            }
            for (name, field) in &config.additional_fields {
                if let Some((definition, existing)) = fields
                    .iter()
                    .zip(&mut entity.fields)
                    .find(|(_, existing)| existing.logical_name == *name)
                {
                    existing.apply_builtin_override(definition, field, entity.role, database)?;
                    continue;
                }
                let rust_name = name.to_snake_case();
                let ident: syn::Ident = syn::parse_str(&rust_name)
                    .or_else(|_| syn::parse_str(&format!("{rust_name}_")))
                    .map_err(|error| format!("invalid additional field `{name}`: {error}"))?;
                let ty = field.storage_type(database)?;
                // Upstream makes organization role fields optional while constructing update-role.
                let ty = if field.required != Some(false)
                    && entity.role != Some(EntityRole::OrganizationRole)
                {
                    ty.to_owned()
                } else {
                    format!("Option<{ty}>")
                };
                let column = resolve_field_name(field.field_name.as_deref(), name).to_owned();
                entity.fields.push(Field {
                    aliases: vec![ident.to_string(), name.clone()],
                    ident,
                    logical_name: name.clone(),
                    ty: syn::parse_str(&ty)
                        .map_err(|error| format!("invalid additional field type: {error}"))?,
                    column: column.clone(),
                    registry_column: None,
                    serialized: Some(column),
                    primary_key: false,
                    reference_override: None,
                    unique: Some(field.unique),
                    attributes: Some(field.clone()),
                });
            }
        }
        if entity.role == Some(EntityRole::Team)
            && let Some(position) = entity
                .fields
                .iter()
                .position(|field| field.registry_column == Some("member_count"))
        {
            // Builtin overrides pair registry fields with their original positions.
            let member_count = entity.fields.remove(position);
            entity.fields.insert(2, member_count);
        }
        if entity.role == Some(EntityRole::Invitation) {
            // Builtin overrides use the registry order before physical field ordering.
            entity
                .fields
                .sort_by_key(|field| match field.registry_column {
                    Some("id" | "organization_id" | "email" | "role") => 0,
                    Some("team_id") => 1,
                    Some("status") => 2,
                    Some("expires_at") => 3,
                    Some("created_at") => 4,
                    Some("inviter_id") => 5,
                    _ => 6,
                });
        }
        entity.registry_columns = entity
            .fields
            .iter()
            .filter_map(|field| {
                field
                    .registry_column
                    .map(|name| (name, field.column.clone()))
            })
            .collect();
        entity.logical_columns = entity
            .fields
            .iter()
            .map(|field| (field.logical_name.clone(), field.column.clone()))
            .collect();
        {
            let mut columns = Vec::<Field>::new();
            for field in entity.fields {
                if let Some(existing) = columns
                    .iter_mut()
                    .find(|existing| existing.column == field.column)
                {
                    if existing.primary_key || field.primary_key {
                        return Err(format!(
                            "model `{}` maps a field to the primary key column `{}`",
                            entity.name, field.column
                        ));
                    }
                    if entity.role == Some(EntityRole::Session)
                        && !entity.session_row_presence
                        && existing
                            .aliases
                            .iter()
                            .chain(&field.aliases)
                            .any(|name| name == "active")
                    {
                        return Err("the independent Session active column cannot share another field's storage".into());
                    }
                    // Upstream keeps the first physical position and the last declaration's attributes.
                    let ident = existing.ident.clone();
                    let mut aliases = std::mem::take(&mut existing.aliases);
                    aliases.extend(field.aliases.iter().cloned());
                    aliases.sort();
                    aliases.dedup();
                    let reference = field.references_id(entity.registry_table);
                    *existing = field;
                    existing.ident = ident;
                    existing.aliases = aliases;
                    existing.reference_override = Some(reference);
                } else {
                    columns.push(field);
                }
            }
            entity.fields = columns;
        }
        if entity.table.is_empty() {
            return Err(format!("model `{}` has an empty table name", entity.name));
        }
        let mut names = BTreeSet::new();
        let mut columns = BTreeSet::new();
        for field in &entity.fields {
            if !names.insert(field.ident.to_string()) {
                return Err(format!(
                    "model `{}` has conflicting Rust field `{}`",
                    entity.name, field.ident
                ));
            }
            if field.column.is_empty() || !columns.insert(&field.column) {
                return Err(format!(
                    "model `{}` has an empty or duplicate database column `{}`",
                    entity.name, field.column
                ));
            }
        }
        Ok(entity)
    }

    pub(crate) fn column(&self, registry_column: &str) -> Option<&str> {
        self.registry_columns
            .get(registry_column)
            .map(String::as_str)
    }

    pub(crate) fn logical_column(&self, name: &str) -> Option<&str> {
        self.logical_columns.get(name).map(String::as_str)
    }

    pub(crate) fn catalog_field(&self, column: &str) -> Option<&'static FieldDef> {
        core_field(self.role, column).or_else(|| {
            if self.session_row_presence {
                return better_auth_schema_registry::plugin_schemas()
                    .iter()
                    .flat_map(|plugin| plugin.session_fields)
                    .find(|field| field.column_name.unwrap_or(field.name) == column);
            }
            if !self.two_factor_native_schema || self.role != Some(EntityRole::User) {
                return None;
            }
            better_auth_schema_registry::plugin_schemas()
                .iter()
                .flat_map(|plugin| plugin.user_fields)
                .find(|field| field.name == "two_factor_enabled" && field.name == column)
        })
    }
}

impl Field {
    pub(crate) fn references_id(&self, table: &str) -> bool {
        self.attributes.as_ref().map_or_else(
            || {
                self.reference_override.unwrap_or_else(|| {
                    better_auth_schema_registry::entity_foreign_keys(table)
                        .iter()
                        .any(|(column, _)| self.registry_column == Some(*column))
                })
            },
            |attributes| {
                attributes
                    .references
                    .as_ref()
                    .is_some_and(|reference| reference.field == "id")
            },
        )
    }

    fn apply_builtin_override(
        &mut self,
        definition: &FieldDef,
        config: &AdditionalField,
        role: Option<EntityRole>,
        database: Database,
    ) -> Result<(), String> {
        if definition.is_primary_key {
            return Ok(());
        }
        let kind = config.storage_type(database)?;
        let kind = if config.required != Some(false) && role != Some(EntityRole::OrganizationRole) {
            kind.to_owned()
        } else {
            format!("Option<{kind}>")
        };
        self.ty = syn::parse_str(&kind)
            .map_err(|error| format!("invalid built-in field type: {error}"))?;
        self.column =
            resolve_field_name(config.field_name.as_deref(), &self.logical_name).to_owned();
        self.serialized = Some(self.column.clone());
        self.unique = Some(config.unique);
        self.attributes = Some(config.clone());
        Ok(())
    }
}

/// Match upstream model names where Rust module names differ.
pub(crate) fn model_name(module: &str) -> String {
    match module {
        "api_key" => "apikey".to_owned(),
        "jwk" => "jwks".to_owned(),
        name => name.to_lower_camel_case(),
    }
}
