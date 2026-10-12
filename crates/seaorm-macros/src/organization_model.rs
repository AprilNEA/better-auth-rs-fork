use super::*;

pub(super) fn generate(
    input: &DeriveInput,
    fields: &syn::FieldsNamed,
    role: EntityRole,
    seaorm_root: &TokenStream,
    core_root: &TokenStream,
) -> syn::Result<TokenStream> {
    let record = match role {
        EntityRole::Organization => "Organization",
        EntityRole::Member => "Member",
        EntityRole::Invitation => "Invitation",
        EntityRole::Team => "Team",
        EntityRole::TeamMember => "TeamMember",
        EntityRole::OrganizationRole => "OrganizationRole",
        _ => {
            return Err(syn::Error::new_spanned(
                input,
                "expected an organization entity role",
            ));
        }
    };
    let record = format_ident!("{record}");
    let core_fields = registry::core_field_names(role);
    let bindings = field_bindings::FieldBindings::new(fields)?;
    let private_columns = registry::core_fields(role)
        .iter()
        .filter_map(|definition| {
            definition
                .adapter_private
                .map(|logical| (definition, logical))
        })
        .map(|(definition, logical)| {
            let name = definition.name;
            let column = bindings
                .get(name)
                .map(|_| bindings.column(name))
                .transpose()?;
            let value = column.map_or_else(|| quote!(None), |column| quote!(Some(Column::#column)));
            Ok(quote!(#name | #logical => Ok(#value),))
        })
        .collect::<syn::Result<Vec<_>>>()?;
    let rename_rule = serde_serialized_name(&input.attrs, "rename_all")?
        .map(|rule| {
            serde_rename_rule::RenameRule::from_rename_all_str(&rule)
                .map_err(|error| syn::Error::new_spanned(input, error.to_string()))
        })
        .transpose()?;
    let mut columns = Vec::new();
    let mut column_aliases = std::collections::BTreeSet::new();
    let mut references = Vec::new();
    let mut stored_values = Vec::new();
    let mut core_columns = Vec::new();
    let mut core_names = Vec::new();
    let mut core_values = Vec::new();
    let mut output_values = Vec::new();
    let mut assignments = Vec::new();
    let mut output = Vec::new();
    for field in &fields.named {
        let Some(ident) = &field.ident else { continue };
        let name = ident.to_string();
        let serialized = serde_serialized_name(&field.attrs, "rename")?.unwrap_or_else(|| {
            rename_rule
                .as_ref()
                .map_or_else(|| name.clone(), |rule| rule.apply_to_field(&name))
        });
        let column = format_ident!(
            "{}",
            serde_rename_rule::RenameRule::PascalCase.apply_to_field(&name)
        );
        let is_core = core_fields.contains(&name.as_str());
        let public_name = if is_core {
            serde_rename_rule::RenameRule::CamelCase.apply_to_field(&name)
        } else {
            serialized.clone()
        };
        let mut aliases = field_aliases::field_aliases(&name, &serialized, &field.attrs)?;
        aliases.retain(|alias| column_aliases.insert(alias.clone()));
        if !aliases.is_empty() {
            columns.push(quote!(#(#aliases)|* => Ok(Column::#column),));
        }
        let stored_value = adapter_record::field_value(ident, seaorm_root);
        stored_values.push(quote!(Column::#column => #stored_value,));
        if is_core {
            core_columns.push(quote!(Column::#column));
            core_names.push(quote!(Column::#column => Some(#public_name),));
        } else {
            core_names.push(quote!(Column::#column => None,));
        }
        let reference = identity::is_reference(role, field)?;
        references.push(quote!(Column::#column => #reference,));
        let decoded = if name == "id" || reference {
            identity::decode(field, core_root, seaorm_root)
        } else {
            adapter_record::decode_field(field, seaorm_root)
        };
        assignments.push(quote!(Column::#column => active.#ident = #seaorm_root::sea_orm::ActiveValue::Set(#decoded),));
    }
    for definition in registry::core_fields(role) {
        let name = definition.name;
        let public_name = registry::canonical_field_name(role, name);
        if let Some(field) = bindings.get(name) {
            let value = adapter_record::field_value(bindings.ident(name)?, seaorm_root);
            core_values.push(quote!((#public_name.to_owned(), #value)));
            if name == "member_count" {
                continue;
            }
            if definition.adapter_private.is_some() || name == "membership_key" {
                output_values.push(quote! {
                    if !fields.fields().contains_key(#public_name) {
                        let _ = projected.remove(#public_name);
                    }
                });
                continue;
            }
            let ident = format_ident!("{name}");
            if matches!(name, "created_at" | "updated_at" | "expires_at") {
                output_values.push(quote! {
                    let value = projected.remove(#public_name);
                    let #ident = if fields.fields().get(#public_name).is_some_and(|field| !matches!(field.field_type, #core_root::user_fields::UserFieldType::Date)) {
                        value.map(#core_root::SchemaValue::Dynamic).unwrap_or_default()
                    } else {
                        #core_root::SchemaValue::from_field(value.unwrap_or_default())
                    };
                });
            } else {
                let reference = identity::is_reference(role, field)?.then(|| quote! {
                    if !fields.fields().contains_key(#public_name) {
                        if let Some(value) = value.as_mut().filter(|value| !value.is_null()) {
                            *value = #core_root::FieldValue::String(#core_root::SchemaValue::<String>::from_field(value.clone()).display_string()?);
                        }
                    }
                });
                output_values.push(if reference.is_some() { quote! {
                    let mut value = projected.remove(#public_name);
                    #reference
                    let #ident = #core_root::SchemaValue::from_field(value.unwrap_or_default());
                }} else { quote! {
                    let #ident = #core_root::SchemaValue::from_field(projected.remove(#public_name).unwrap_or_default());
                }});
            }
            output.push(quote!(#ident));
        }
    }
    let ident = &input.ident;
    let physical_lookup = field_aliases::physical_lookup(seaorm_root);
    let record_fields = quote! {
            let core = #core_root::FieldMap::from_iter([#(#core_values),*]);
            let mut storage = #core_root::FieldMap::new();
            for (name, field) in fields.fields() {
                if name == "id" { continue; }
                let storage_name = #core_root::store::schema::resolve_field_name(field.field_name.as_deref(), name);
                let value = match Self::column(storage_name)? { #(#stored_values)* };
                let _ = storage.insert(storage_name.to_owned(), value);
            }
            Ok(#core_root::user_fields::AdapterRecord::new(core, storage))
    };
    Ok(quote! {
        impl #seaorm_root::SeaOrmOrganizationModel for #ident {
            type Record = #core_root::#record;
            type Entity = Entity;
            type ActiveModel = ActiveModel;
            type Column = Column;
            fn column(name: &str) -> #core_root::AuthResult<Column> {
                #physical_lookup
                match name { #(#columns)* _ => Err(#core_root::AuthError::config(format!("Unknown organization model column: {name}"))) }
            }
            fn private_column(name: &str) -> #core_root::AuthResult<Option<Column>> {
                match name { #(#private_columns)* _ => Err(#core_root::AuthError::config(format!("Unknown private organization model column: {name}"))) }
            }
            fn is_core_column(column: &Column) -> bool {
                matches!(column, #(#core_columns)|*)
            }
            fn core_field_name(column: &Column) -> Option<&'static str> {
                match column { #(#core_names)* }
            }
            fn record_fields(&self, fields: &#core_root::user_fields::UserConfig) -> #core_root::AuthResult<#core_root::user_fields::AdapterRecord> {
                #record_fields
            }
            fn record_from_fields(&self, fields: &#core_root::user_fields::UserConfig, mut projected: #core_root::FieldMap) -> #core_root::AuthResult<Self::Record> {
                let field_order = projected.keys().cloned().collect();
                #(#output_values)*
                Ok(#core_root::#record { #(#output,)* field_order, additional_fields: projected })
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
