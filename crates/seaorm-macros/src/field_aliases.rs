use proc_macro2::TokenStream;
use quote::quote;
use syn::{Attribute, DeriveInput, Expr, FieldsNamed, Lit, Meta, Token, punctuated::Punctuated};

pub(super) fn generate(
    input: &DeriveInput,
    fields: &FieldsNamed,
    role: super::EntityRole,
    seaorm: &TokenStream,
) -> syn::Result<TokenStream> {
    let rule = super::serde_serialized_name(&input.attrs, "rename_all")?
        .map(|rule| {
            serde_rename_rule::RenameRule::from_rename_all_str(&rule)
                .map_err(|error| syn::Error::new_spanned(input, error.to_string()))
        })
        .transpose()?;
    let mut serialized_names = Vec::new();
    let mut serialized_columns = Vec::new();
    let mut seen = std::collections::BTreeSet::new();
    for field in &fields.named {
        let Some(ident) = &field.ident else { continue };
        let rust_name = ident.to_string();
        let name = super::serde_serialized_name(&field.attrs, "rename")?.unwrap_or_else(|| {
            rule.as_ref()
                .map_or_else(|| rust_name.clone(), |rule| rule.apply_to_field(&rust_name))
        });
        let column = quote::format_ident!(
            "{}",
            serde_rename_rule::RenameRule::PascalCase.apply_to_field(&rust_name)
        );
        serialized_columns.push(quote!(Column::#column => #name,));
        let mut aliases = field_aliases(role, &rust_name, &name, &field.attrs)?;
        aliases.retain(|alias| seen.insert(alias.clone()));
        if !aliases.is_empty() {
            serialized_names.push(quote!(#(#aliases)|* => #name,));
        }
    }
    Ok(quote! {
        fn serialized_field_name(name: &str) -> &str {
            if let Some(column) = <Column as #seaorm::sea_orm::Iterable>::iter()
                .find(|column| #seaorm::sea_orm::IdenStatic::as_str(column) == name)
            {
                return match column { #(#serialized_columns)* };
            }
            match name { #(#serialized_names)* _ => name }
        }
    })
}

pub(super) fn field_aliases(
    role: super::EntityRole,
    rust_name: &str,
    serialized: &str,
    attrs: &[Attribute],
) -> syn::Result<Vec<String>> {
    let mut aliases = vec![
        rust_name.to_owned(),
        serialized.to_owned(),
        serde_rename_rule::RenameRule::CamelCase.apply_to_field(rust_name),
        super::registry::canonical_field_name(role, rust_name),
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
    for alias in super::field_bindings::FieldOptions::parse_attributes(attrs)?.aliases {
        aliases.push(serde_rename_rule::RenameRule::CamelCase.apply_to_field(&alias));
        aliases.push(super::registry::canonical_field_name(role, &alias));
        aliases.push(alias);
    }
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

#[cfg(test)]
mod tests {
    use super::*;
    use syn::parse::Parser;

    #[test]
    fn native_aliases_keep_registry_spelling_after_column_folding() -> syn::Result<()> {
        for (role, declaration, canonical) in [
            (
                super::super::EntityRole::Passkey,
                quote!(#[auth(alias = "credential_id")] shared: String),
                "credentialID",
            ),
            (
                super::super::EntityRole::ApiKey,
                quote!(#[auth(alias = "key_hash")] shared: String),
                "key",
            ),
            (
                super::super::EntityRole::Session,
                quote!(#[auth(alias = "user_agent")] shared: String),
                "userAgent",
            ),
        ] {
            let field = syn::Field::parse_named.parse2(declaration)?;
            let aliases = field_aliases(role, "shared", "stored_value", &field.attrs)?;
            assert!(aliases.iter().any(|alias| alias == canonical));
            assert!(aliases.iter().any(|alias| alias == "stored_value"));
        }
        Ok(())
    }
}
