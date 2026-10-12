use proc_macro2::Ident;
use quote::format_ident;
use std::collections::BTreeMap;
use syn::{Attribute, Field, FieldsNamed, LitBool, LitStr};

pub(super) fn methods(
    input: &syn::DeriveInput,
    fields: &FieldsNamed,
    role: super::EntityRole,
    row_presence: bool,
    seaorm: &proc_macro2::TokenStream,
    core: &proc_macro2::TokenStream,
) -> syn::Result<proc_macro2::TokenStream> {
    use quote::quote;
    let bindings = FieldBindings::new(fields)?;
    let rule = super::serde_serialized_name(&input.attrs, "rename_all")?
        .map(|rule| {
            serde_rename_rule::RenameRule::from_rename_all_str(&rule)
                .map_err(|error| syn::Error::new_spanned(input, error.to_string()))
        })
        .transpose()?;
    let mut columns = Vec::new();
    let mut assignments = Vec::new();
    let mut seen = std::collections::BTreeSet::new();
    for field in &fields.named {
        let ident = field
            .ident
            .as_ref()
            .ok_or_else(|| syn::Error::new_spanned(field, "AuthEntity requires named fields"))?;
        let name = ident.to_string();
        let column = bindings.column(&name)?;
        let serialized =
            super::serde_serialized_name(&field.attrs, "rename")?.unwrap_or_else(|| {
                rule.as_ref()
                    .map_or_else(|| name.clone(), |rule| rule.apply_to_field(&name))
            });
        let mut aliases =
            super::field_aliases::field_aliases(role, &name, &serialized, &field.attrs)?;
        if row_presence && aliases.iter().any(|alias| alias == "active") {
            return Err(syn::Error::new_spanned(
                field,
                "row_presence session models cannot expose an active field",
            ));
        }
        aliases.retain(|alias| seen.insert(alias.clone()));
        if !aliases.is_empty() {
            columns.push(quote!(#(#aliases)|* => Ok(Column::#column),));
        }
        let assignment = bindings.assignment(&name, role, seaorm, core)?;
        assignments.push(quote!(Column::#column => { #assignment }));
    }
    let physical = super::field_aliases::physical_lookup(seaorm);
    Ok(quote! {
        fn field_column(name: &str) -> #core::AuthResult<Column> {
            #physical
            match name {
                #(#columns)*
                _ => Err(#core::AuthError::config(format!("Unknown reference model field: {name}"))),
            }
        }
        fn native_json_field(name: &str) -> bool {
            Self::field_column(name).is_ok_and(|column| matches!(
                #seaorm::sea_orm::ColumnTrait::def(&column).get_column_type(),
                #seaorm::sea_orm::ColumnType::Json | #seaorm::sea_orm::ColumnType::JsonBinary
            ))
        }
        fn apply_fields(active: &mut Self::ActiveModel, fields: #core::FieldMap) -> #core::AuthResult<()> {
            for (name, value) in fields {
                match Self::field_column(&name)? { #(#assignments)* }
            }
            Ok(())
        }
    })
}

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

    pub(super) fn assignment(
        &self,
        name: &str,
        role: super::EntityRole,
        seaorm: &proc_macro2::TokenStream,
        core: &proc_macro2::TokenStream,
    ) -> syn::Result<proc_macro2::TokenStream> {
        let field = self.require(name)?;
        let ident = self.ident(name)?;
        let primary_key = self.get("id").is_some_and(|id| id.ident == field.ident);
        let decoded = if primary_key || super::identity::is_reference(role, field)? {
            super::identity::decode(field, core, seaorm)
        } else {
            super::adapter_record::decode_field(field, seaorm)
        };
        Ok(quote::quote!(active.#ident = #seaorm::sea_orm::ActiveValue::Set(#decoded);))
    }
}
