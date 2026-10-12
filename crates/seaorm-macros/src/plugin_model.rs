use super::*;

pub(super) fn record_name(role: EntityRole) -> Option<&'static str> {
    Some(match role {
        EntityRole::ApiKey => "ApiKey",
        EntityRole::DeviceCode => "DeviceCode",
        EntityRole::Passkey => "Passkey",
        EntityRole::TwoFactor => "TwoFactor",
        EntityRole::Jwk => "Jwk",
        EntityRole::WalletAddress => "WalletAddress",
        EntityRole::RateLimit => "RateLimitRecord",
        _ => return None,
    })
}

pub(super) fn generate(
    input: &DeriveInput,
    fields: &syn::FieldsNamed,
    options: &EntityOptions,
    (seaorm_root, core_root): (&TokenStream, &TokenStream),
) -> syn::Result<TokenStream> {
    let role = options.role;
    let record = record_name(role)
        .ok_or_else(|| syn::Error::new_spanned(input, "expected a plugin entity role"))?;
    let record = format_ident!("{record}");
    let record = if role == EntityRole::RateLimit {
        quote!(#core_root::store::#record)
    } else {
        quote!(#core_root::#record)
    };
    let bindings = field_bindings::FieldBindings::new(fields)?;
    let rename_all = serde_serialized_name(&input.attrs, "rename_all")?
        .map(|rule| {
            serde_rename_rule::RenameRule::from_rename_all_str(&rule)
                .map_err(|error| syn::Error::new_spanned(input, error.to_string()))
        })
        .transpose()?;
    let mut columns = Vec::new();
    let mut column_aliases = std::collections::BTreeSet::new();
    let mut core_columns = Vec::new();
    let mut values = Vec::new();
    let mut references = Vec::new();
    let mut assignments = Vec::new();
    let mut raw_output = Vec::new();
    for field in &fields.named {
        let Some(ident) = &field.ident else { continue };
        let name = ident.to_string();
        let column = format_ident!(
            "{}",
            serde_rename_rule::RenameRule::PascalCase.apply_to_field(&name)
        );
        let serialized = serde_serialized_name(&field.attrs, "rename")?.unwrap_or_else(|| {
            rename_all
                .as_ref()
                .map_or_else(|| name.clone(), |rule| rule.apply_to_field(&name))
        });
        let mut aliases = field_aliases::field_aliases(role, &name, &serialized, &field.attrs)?;
        aliases.retain(|alias| column_aliases.insert(alias.clone()));
        if !aliases.is_empty() {
            columns.push(quote!(#(#aliases)|* => Ok(Column::#column),));
        }
        let reference = identity::is_reference(role, field)?;
        references.push(quote!(Column::#column => #reference,));
        let assignment = bindings.assignment(&name, role, seaorm_root, core_root)?;
        assignments.push(quote!(Column::#column => { #assignment }));
        let stored_value = adapter_record::field_value(ident, seaorm_root);
        values.push(quote!(Column::#column => #stored_value,));
        let logical = registry::core_fields(role)
            .iter()
            .find(|definition| {
                bindings
                    .get(definition.name)
                    .is_some_and(|field| field.ident.as_ref() == Some(ident))
            })
            .map(|definition| registry::canonical_field_name(role, definition.name));
        let logical = logical.map_or_else(|| quote!(None), |logical| quote!(Some(#logical)));
        core_columns.push(quote!(Column::#column => #logical,));
    }
    for definition in registry::core_fields(role) {
        let Some(field) = bindings.get(definition.name) else {
            continue;
        };
        let ident = field
            .ident
            .as_ref()
            .ok_or_else(|| syn::Error::new_spanned(field, "AuthEntity requires named fields"))?;
        let logical = registry::canonical_field_name(role, definition.name);
        let logical_value = if definition.name == "id" {
            quote!(#core_root::FieldValue::String(self.#ident.to_string()))
        } else {
            adapter_record::field_value(ident, seaorm_root)
        };
        raw_output.push(quote!((#logical.to_owned(), #logical_value),));
    }
    let passkey_storage = options.native_passkey.then(|| {
        quote! {
            fn passkey_storage() -> #core_root::PasskeyStorage {
                #core_root::PasskeyStorage::Native
            }
        }
    });
    let two_factor_storage = options.native_two_factor.then(|| {
        quote! {
            fn two_factor_storage() -> #core_root::TwoFactorStorage {
                #core_root::TwoFactorStorage::Native
            }
        }
    });
    let declaration = options.model_name.as_ref().map(|name| {
        quote! {
            fn model_declaration() -> Option<#core_root::schema::ModelDeclaration> {
                Some(#core_root::schema::ModelDeclaration {
                    role: #core_root::schema::EntityRole::RateLimit,
                    model_name: Some(#name),
                    fields: None,
                })
            }
        }
    });
    let ident = &input.ident;
    let logical = quote!(#core_root::FieldMap::from_iter([#(#raw_output)*]));
    let physical_lookup = field_aliases::physical_lookup(seaorm_root);
    Ok(quote! {
        impl #seaorm_root::SeaOrmPluginModel for #ident {
            type Record = #record;
            type Entity = Entity;
            type ActiveModel = ActiveModel;
            type Column = Column;
            #declaration
            #passkey_storage
            #two_factor_storage
            fn column(name: &str) -> #core_root::AuthResult<Column> {
                #physical_lookup
                match name { #(#columns)* _ => Err(#core_root::AuthError::config(format!("Unknown plugin model column: {name}"))) }
            }
            fn core_field_name(column: &Column) -> Option<&'static str> {
                match column { #(#core_columns)* }
            }
            fn record_fields(&self, fields: &#core_root::user_fields::UserConfig) -> #core_root::AuthResult<#core_root::user_fields::AdapterRecord> {
                let mut storage = #core_root::FieldMap::new();
                for (name, field) in fields.fields() {
                    let name = #core_root::store::schema::resolve_field_name(field.field_name.as_deref(), name);
                    let value = match Self::column(name)? { #(#values)* };
                    let _ = storage.insert(name.to_owned(), value);
                }
                Ok(#core_root::user_fields::AdapterRecord::new(#logical, storage))
            }
            fn record(&self) -> #core_root::AuthResult<Self::Record> {
                <#record as #core_root::FromFieldMap>::from_field_values(#logical)
            }
            fn is_id_reference(column: &Column) -> bool {
                match column { #(#references)* }
            }
            fn apply_fields(active: &mut ActiveModel, fields: #core_root::FieldMap) -> #core_root::AuthResult<()> {
                for (name, value) in fields {
                    match Self::column(&name)? { #(#assignments)* }
                }
                Ok(())
            }
        }
    })
}
