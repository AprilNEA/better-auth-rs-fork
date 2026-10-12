use proc_macro2::TokenStream;
use quote::quote;
use syn::{Attribute, DeriveInput, Expr, FieldsNamed, Lit, Meta, Token, punctuated::Punctuated};

pub(super) fn generate(
    input: &DeriveInput,
    fields: &FieldsNamed,
    known: &[&str],
) -> syn::Result<TokenStream> {
    let rule = super::serde_serialized_name(&input.attrs, "rename_all")?
        .map(|rule| {
            serde_rename_rule::RenameRule::from_rename_all_str(&rule)
                .map_err(|error| syn::Error::new_spanned(input, error.to_string()))
        })
        .transpose()?;
    let mut serialized_names = Vec::new();
    for field in &fields.named {
        let Some(ident) = &field.ident else { continue };
        let rust_name = ident.to_string();
        let name = if known.contains(&rust_name.as_str()) {
            serde_rename_rule::RenameRule::CamelCase.apply_to_field(&rust_name)
        } else {
            super::serde_serialized_name(&field.attrs, "rename")?.unwrap_or_else(|| {
                rule.as_ref()
                    .map_or_else(|| rust_name.clone(), |rule| rule.apply_to_field(&rust_name))
            })
        };
        if !known.contains(&rust_name.as_str()) {
            let aliases = field_aliases(&rust_name, &name, &field.attrs)?;
            serialized_names.push(quote!(#(#aliases)|* => #name,));
        }
    }
    Ok(quote! {
        fn serialized_field_name(name: &str) -> &str {
            match name { #(#serialized_names)* _ => name }
        }
    })
}

pub(super) fn field_aliases(
    rust_name: &str,
    serialized: &str,
    attrs: &[Attribute],
) -> syn::Result<Vec<String>> {
    let mut aliases = vec![
        rust_name.to_owned(),
        serialized.to_owned(),
        serde_rename_rule::RenameRule::CamelCase.apply_to_field(rust_name),
    ];
    for attr in attrs.iter().filter(|attr| attr.path().is_ident("sea_orm")) {
        for meta in attr.parse_args_with(Punctuated::<Meta, Token![,]>::parse_terminated)? {
            if let Meta::NameValue(value) = meta
                && value.path.is_ident("column_name")
                && let Expr::Lit(value) = value.value
                && let Lit::Str(value) = value.lit
            {
                aliases.push(value.value());
            }
        }
    }
    aliases.extend(super::field_bindings::FieldOptions::parse_attributes(attrs)?.aliases);
    aliases.sort();
    aliases.dedup();
    Ok(aliases)
}

pub(super) fn physical_lookup(seaorm: &TokenStream) -> TokenStream {
    quote! {
        if let Some(column) = <Column as #seaorm::sea_orm::Iterable>::iter()
            .find(|column| #seaorm::sea_orm::IdenStatic::as_str(column) == name)
        {
            return Ok(column);
        }
    }
}
