use proc_macro2::Ident;
use quote::format_ident;
use std::collections::BTreeMap;
use syn::{Attribute, Field, FieldsNamed, LitBool, LitStr};

#[derive(Default)]
pub(super) struct FieldOptions {
    pub aliases: Vec<String>,
    pub reference: Option<bool>,
}

impl FieldOptions {
    pub(super) fn parse(field: &Field) -> syn::Result<Self> {
        Self::parse_attributes(&field.attrs)
    }

    pub(super) fn parse_attributes(attributes: &[Attribute]) -> syn::Result<Self> {
        let mut options = Self::default();
        for attribute in attributes
            .iter()
            .filter(|attribute| attribute.path().is_ident("auth"))
        {
            attribute.parse_nested_meta(|meta| {
                if meta.path.is_ident("alias") {
                    let alias = meta.value()?.parse::<LitStr>()?;
                    if alias.value().is_empty() {
                        return Err(meta.error("an auth field alias must not be empty"));
                    }
                    options.aliases.push(alias.value());
                } else if meta.path.is_ident("reference") {
                    options.reference = Some(if meta.input.peek(syn::Token![=]) {
                        meta.value()?.parse::<LitBool>()?.value
                    } else {
                        true
                    });
                } else {
                    return Err(meta.error("expected `alias` or `reference`"));
                }
                Ok(())
            })?;
        }
        Ok(options)
    }
}

pub(super) struct FieldBindings<'a> {
    fields: BTreeMap<String, &'a Field>,
}

impl<'a> FieldBindings<'a> {
    pub(super) fn new(fields: &'a FieldsNamed) -> syn::Result<Self> {
        let mut bindings = BTreeMap::new();
        for field in &fields.named {
            let ident = field.ident.as_ref().ok_or_else(|| {
                syn::Error::new_spanned(field, "AuthEntity requires named fields")
            })?;
            for name in
                std::iter::once(ident.to_string()).chain(FieldOptions::parse(field)?.aliases)
            {
                if let Some(previous) = bindings.insert(name.clone(), field)
                    && previous.ident != field.ident
                {
                    return Err(syn::Error::new_spanned(
                        field,
                        format!("auth field alias `{name}` identifies multiple columns"),
                    ));
                }
            }
        }
        Ok(Self { fields: bindings })
    }

    pub(super) fn get(&self, name: &str) -> Option<&'a Field> {
        self.fields.get(name).copied()
    }

    pub(super) fn require(&self, name: &str) -> syn::Result<&'a Field> {
        self.get(name).ok_or_else(|| {
            syn::Error::new(
                proc_macro2::Span::call_site(),
                format!("missing required auth field `{name}`"),
            )
        })
    }

    pub(super) fn ident(&self, name: &str) -> syn::Result<&'a Ident> {
        self.require(name)?.ident.as_ref().ok_or_else(|| {
            syn::Error::new(
                proc_macro2::Span::call_site(),
                "AuthEntity requires named fields",
            )
        })
    }

    pub(super) fn column(&self, name: &str) -> syn::Result<Ident> {
        Ok(format_ident!(
            "{}",
            serde_rename_rule::RenameRule::PascalCase
                .apply_to_field(&self.ident(name)?.to_string())
        ))
    }
}
