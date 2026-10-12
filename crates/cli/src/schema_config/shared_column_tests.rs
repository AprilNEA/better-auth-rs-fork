use super::*;
use quote::ToTokens;

#[test]
fn shared_columns_preserve_the_captured_catalog_order_and_last_storage_type()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../tests/fixtures/shared-column-1.7.6.json"
    ))?;
    let observations = fixture.as_array().ok_or("Missing backend observations")?;
    let cases = observations
        .iter()
        .find(|value| value["backend"] == "sqlite")
        .and_then(|value| value["cases"].as_array())
        .ok_or("Missing SQLite cases")?;
    assert_eq!(cases.len(), 30);
    for case in cases {
        let model = case["model"].as_str().ok_or("Missing model")?;
        let config: SchemaConfig = serde_json::from_value(case["configuration"].clone())?;
        let generated = crate::generate::generate_schema(
            &["organization".into()],
            &config,
            false,
            IdGeneration::Random,
            Database::Sqlite,
            SchemaOptions::default(),
        )?;
        let source = syn::parse_file(&generated)?;
        let module = source
            .items
            .iter()
            .find_map(|item| match item {
                syn::Item::Mod(module) if module.ident == model.to_snake_case() => Some(module),
                _ => None,
            })
            .ok_or("Missing generated model module")?;
        let (_, items) = module.content.as_ref().ok_or("Missing module items")?;
        let model = items
            .iter()
            .find_map(|item| match item {
                syn::Item::Struct(model) if model.ident == "Model" => Some(model),
                _ => None,
            })
            .ok_or("Missing generated model")?;
        let columns = model
            .fields
            .iter()
            .map(|field| {
                let mut column = field
                    .ident
                    .as_ref()
                    .ok_or("Unnamed generated field")?
                    .to_string();
                for attribute in field
                    .attrs
                    .iter()
                    .filter(|attribute| attribute.path().is_ident("sea_orm"))
                {
                    attribute.parse_nested_meta(|meta| {
                        if meta.path.is_ident("column_name") {
                            column = meta.value()?.parse::<syn::LitStr>()?.value();
                        } else if meta.input.peek(syn::Token![=]) {
                            let _ = meta.value()?.parse::<syn::Expr>()?;
                        }
                        Ok(())
                    })?;
                }
                Ok((column, field))
            })
            .collect::<Result<Vec<_>, Box<dyn std::error::Error>>>()?;
        let catalog = case["catalog"]["catalog"]["columns"]
            .as_array()
            .ok_or("Missing catalog columns")?;
        assert_eq!(
            columns
                .iter()
                .map(|(name, _)| name.as_str())
                .collect::<Vec<_>>(),
            catalog
                .iter()
                .map(|column| column["name"].as_str().unwrap_or_default())
                .collect::<Vec<_>>(),
            "{} {}",
            case["model"],
            case["mode"]
        );
        let (_, field) = columns
            .iter()
            .find(|(name, _)| name == "shared_value")
            .ok_or("Missing shared member")?;
        let captured = catalog
            .iter()
            .find(|column| column["name"] == "shared_value")
            .ok_or("Missing captured shared column")?;
        let expected = match captured["type"].as_str() {
            Some("TEXT") => quote::quote!(Option<String>),
            Some("INTEGER") => quote::quote!(Option<better_auth::seaorm::SqlNumber>),
            _ => return Err("Unexpected shared column storage type".into()),
        };
        assert_eq!(
            field.ty.to_token_stream().to_string(),
            expected.to_string(),
            "{} {}",
            case["model"],
            case["mode"]
        );
    }
    Ok(())
}
