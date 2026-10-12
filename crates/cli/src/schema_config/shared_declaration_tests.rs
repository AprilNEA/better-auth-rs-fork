use super::*;
use quote::ToTokens;
use serde_json::json;

#[test]
fn native_replacements_use_logical_names_and_backend_storage_types() -> Result<(), String> {
    let config: SchemaConfig = serde_json::from_str(include_str!(
        "../../../../compat-tests/schema-consumer/shared-declarations-schema.json"
    ))
    .map_err(|error| error.to_string())?;
    for database in [Database::Sqlite, Database::Postgres, Database::Mysql] {
        let source = crate::generate::generate_schema(
            &["organization".into()],
            &config,
            true,
            IdGeneration::Random,
            database,
            Default::default(),
        )?;
        let generated = syn::parse_file(&source).map_err(|error| error.to_string())?;
        let modules = generated
            .items
            .iter()
            .filter_map(|item| match item {
                syn::Item::Mod(module) => module
                    .content
                    .as_ref()
                    .map(|(_, items)| (module.ident.to_string(), items)),
                _ => None,
            })
            .collect::<BTreeMap<_, _>>();
        for (model, configuration) in &config.0 {
            let module = model.to_snake_case();
            let fields = modules
                .get(&module)
                .and_then(|items| {
                    items.iter().find_map(|item| match item {
                        syn::Item::Struct(model) if model.ident == "Model" => Some(&model.fields),
                        _ => None,
                    })
                })
                .ok_or_else(|| format!("Missing generated model {model}"))?;
            if model == "rateLimit" {
                assert!(fields.iter().all(|field| {
                    field
                        .ident
                        .as_ref()
                        .is_none_or(|name| name != "discarded_field")
                }));
                let field = fields
                    .iter()
                    .find(|field| {
                        field
                            .ident
                            .as_ref()
                            .is_some_and(|name| name == "last_request")
                    })
                    .ok_or("Missing native RateLimit lastRequest")?;
                assert_eq!(column_name(field)?, "stored_last_request");
                assert_eq!(field.ty.to_token_stream().to_string(), "i64");
                continue;
            }
            for (name, declaration) in &configuration.additional_fields {
                let field = fields
                    .iter()
                    .find(|field| {
                        field
                            .ident
                            .as_ref()
                            .is_some_and(|ident| *ident == name.to_snake_case())
                    })
                    .ok_or_else(|| format!("Missing generated field {model}.{name}"))?;
                let expected_column = if name == "label" {
                    "stored_label"
                } else {
                    name
                };
                assert_eq!(column_name(field)?, expected_column, "{model}.{name}");
                if matches!(&declaration.field_type, FieldType::Name(kind) if kind == "json") {
                    let kind = if database == Database::Sqlite {
                        "better_auth::seaorm::SqlText"
                    } else {
                        "Json"
                    };
                    let kind = if declaration.required == Some(false) {
                        format!("Option<{kind}>")
                    } else {
                        kind.to_owned()
                    };
                    let expected: syn::Type =
                        syn::parse_str(&kind).map_err(|error| error.to_string())?;
                    assert_eq!(
                        field.ty.to_token_stream().to_string(),
                        expected.to_token_stream().to_string(),
                        "{model}.{name}"
                    );
                }
            }
        }
    }
    Ok(())
}

#[test]
fn declared_team_member_fields_use_the_existing_reference_policy() -> Result<(), String> {
    let config: SchemaConfig = serde_json::from_value(json!({
        "teamMember": { "additionalFields": {
            "externalOwner": { "type": "number", "required": false,
                "references": { "model": "user", "field": "id" } }
        } }
    }))
    .map_err(|error| error.to_string())?;
    config.validate()?;
    let source = crate::generate::generate_schema(
        &["organization".into()],
        &config,
        false,
        IdGeneration::Serial,
        Database::Postgres,
        Default::default(),
    )?;
    let fields = super::json_storage_tests::model_fields(&source, "team_member");
    let owner = fields
        .get("external_owner")
        .ok_or("Missing declared owner")?;
    assert_eq!(
        owner.ty.to_token_stream().to_string(),
        quote::quote!(Option<i32>).to_string()
    );
    assert_eq!(
        super::json_storage_tests::reference_policy(owner).map_err(|error| error.to_string())?,
        Some(true)
    );
    Ok(())
}

fn column_name(field: &syn::Field) -> Result<String, String> {
    let mut name = field
        .ident
        .as_ref()
        .ok_or("Expected a named generated field")?
        .to_string();
    for attribute in field
        .attrs
        .iter()
        .filter(|attribute| attribute.path().is_ident("sea_orm"))
    {
        attribute
            .parse_nested_meta(|meta| {
                if meta.path.is_ident("column_name") {
                    name = meta.value()?.parse::<syn::LitStr>()?.value();
                } else if meta.input.peek(syn::Token![=]) {
                    let _ = meta.value()?.parse::<syn::Expr>()?;
                }
                Ok(())
            })
            .map_err(|error| error.to_string())?;
    }
    Ok(name)
}

#[test]
fn organization_generation_separates_native_columns_from_legacy_adapter_storage()
-> Result<(), String> {
    for database in [Database::Sqlite, Database::Postgres, Database::Mysql] {
        for legacy in [false, true] {
            let source = crate::generate::generate_schema(
                &["organization".into()],
                &SchemaConfig::default(),
                false,
                IdGeneration::Random,
                database,
                SchemaOptions {
                    organization_legacy_schema: legacy,
                    ..Default::default()
                },
            )?;
            let generated = syn::parse_file(&source).map_err(|error| error.to_string())?;
            let fields = generated
                .items
                .iter()
                .find_map(|item| match item {
                    syn::Item::Mod(module) if module.ident == "organization" => {
                        module.content.as_ref().and_then(|(_, items)| {
                            items.iter().find_map(|item| match item {
                                syn::Item::Struct(model) if model.ident == "Model" => {
                                    Some(&model.fields)
                                }
                                _ => None,
                            })
                        })
                    }
                    _ => None,
                })
                .ok_or("Missing generated Organization")?;
            let columns = fields
                .iter()
                .map(column_name)
                .collect::<Result<Vec<_>, _>>()?;
            let expected = if legacy {
                vec![
                    "id",
                    "name",
                    "slug",
                    "logo",
                    "metadata",
                    "created_at",
                    "updated_at",
                ]
            } else {
                vec!["id", "name", "slug", "logo", "createdAt", "metadata"]
            };
            assert_eq!(columns, expected);
        }
    }
    Ok(())
}
