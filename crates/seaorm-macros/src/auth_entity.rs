use better_auth_schema_registry::{self as registry, EntityRole};
use proc_macro_crate::{FoundCrate, crate_name};
use proc_macro2::{Ident, Span, TokenStream};
use quote::{format_ident, quote};
use syn::{
    Attribute, Data, DeriveInput, Expr, Fields, Lit, LitStr, Meta, Token, punctuated::Punctuated,
};
#[path = "organization_model.rs"]
mod organization_model;
use organization_model::generate as gen_organization_model;
#[path = "adapter_record.rs"]
mod adapter_record;
#[path = "field_aliases.rs"]
mod field_aliases;
#[path = "field_bindings.rs"]
mod field_bindings;
#[path = "identity.rs"]
mod identity;
#[path = "plugin_model.rs"]
mod plugin_model;
#[path = "session_model.rs"]
mod session_model;
#[path = "user_model.rs"]
mod user_model;

fn serde_serialized_name(attrs: &[Attribute], key: &str) -> syn::Result<Option<String>> {
    for attr in attrs.iter().filter(|attr| attr.path().is_ident("serde")) {
        for meta in attr.parse_args_with(Punctuated::<Meta, Token![,]>::parse_terminated)? {
            if !meta.path().is_ident(key) {
                continue;
            }
            let value = match meta {
                Meta::NameValue(value) => Some(value.value),
                Meta::List(list) => list
                    .parse_args_with(Punctuated::<Meta, Token![,]>::parse_terminated)?
                    .into_iter()
                    .find_map(|meta| match meta {
                        Meta::NameValue(value) if value.path.is_ident("serialize") => {
                            Some(value.value)
                        }
                        _ => None,
                    }),
                Meta::Path(_) => None,
            };
            if let Some(Expr::Lit(value)) = value
                && let Lit::Str(value) = value.lit
            {
                return Ok(Some(value.value()));
            }
        }
    }
    Ok(None)
}

fn found_crate_tokens(name: &str) -> Option<TokenStream> {
    match crate_name(name).ok()? {
        FoundCrate::Itself => {
            // `Itself` means the Cargo.toml that triggered compilation lists
            // this crate as its own package name.  Examples and integration
            // tests compile as separate binaries that link the crate
            // externally, so `crate::` would be wrong — use the extern name.
            let ident = Ident::new(&name.replace('-', "_"), Span::call_site());
            Some(quote!(::#ident))
        }
        FoundCrate::Name(name) => {
            let ident = Ident::new(&name, Span::call_site());
            Some(quote!(::#ident))
        }
    }
}

fn resolve_roots() -> syn::Result<(TokenStream, TokenStream)> {
    if let Some(better_auth_root) = found_crate_tokens("better-auth") {
        return Ok((
            quote!(#better_auth_root::seaorm),
            quote!(#better_auth_root::__private_core),
        ));
    }
    if let Some(seaorm_root) = found_crate_tokens("better-auth-seaorm") {
        let core_root = quote!(#seaorm_root::__private_core);
        return Ok((seaorm_root, core_root));
    }
    Err(syn::Error::new(
        Span::call_site(),
        "AuthEntity requires better-auth with the `seaorm2` feature or a direct better-auth-seaorm dependency",
    ))
}

pub(crate) fn derive_auth_entity(input: &DeriveInput) -> TokenStream {
    let (seaorm_root, core_root) = match resolve_roots() {
        Ok(roots) => roots,
        Err(error) => return error.to_compile_error(),
    };
    let options = match parse_options(input) {
        Ok(options) => options,
        Err(err) => return err.to_compile_error(),
    };
    let EntityOptions {
        role, row_presence, ..
    } = options;

    let fields = match &input.data {
        Data::Struct(data) => match &data.fields {
            Fields::Named(fields) => fields,
            _ => {
                return syn::Error::new_spanned(
                    &input.ident,
                    "AuthEntity requires a struct with named fields",
                )
                .to_compile_error();
            }
        },
        _ => {
            return syn::Error::new_spanned(&input.ident, "AuthEntity requires a struct")
                .to_compile_error();
        }
    };

    let plugin_record = plugin_model::record_name(role).is_some();
    let bindings = match field_bindings::FieldBindings::new(fields) {
        Ok(bindings) => bindings,
        Err(error) => return error.to_compile_error(),
    };

    if let Some(missing) = registry::core_fields(role).iter().find(|required| {
        !(required.adapter_private.is_some()
            || plugin_record && required.name != "id"
            || row_presence && required.name == "active")
            && bindings.get(required.name).is_none()
    }) {
        return syn::Error::new_spanned(
            &input.ident,
            format!(
                "missing required auth field `{}` for this role",
                missing.name
            ),
        )
        .to_compile_error();
    }

    let ident = &input.ident;
    let field_methods = match field_bindings::methods(
        input,
        fields,
        role,
        row_presence,
        &seaorm_root,
        &core_root,
    ) {
        Ok(methods) => methods,
        Err(error) => return error.to_compile_error(),
    };
    let aliases = if matches!(role, EntityRole::Session | EntityRole::User) {
        match field_aliases::generate(input, fields, role, &seaorm_root) {
            Ok(methods) => methods,
            Err(error) => return error.to_compile_error(),
        }
    } else {
        TokenStream::new()
    };

    let record_fields = (|| -> syn::Result<TokenStream> {
        let rule = serde_serialized_name(&input.attrs, "rename_all")?
            .map(|rule| {
                serde_rename_rule::RenameRule::from_rename_all_str(&rule)
                    .map_err(|error| syn::Error::new_spanned(input, error.to_string()))
            })
            .transpose()?;
        let values = fields
            .named
            .iter()
            .map(|field| {
                let ident = field.ident.as_ref().ok_or_else(|| {
                    syn::Error::new_spanned(field, "AuthEntity requires named fields")
                })?;
                let name = ident.to_string();
                let name = serde_serialized_name(&field.attrs, "rename")?.unwrap_or_else(|| {
                    rule.as_ref()
                        .map_or_else(|| name.clone(), |rule| rule.apply_to_field(&name))
                });
                let value = adapter_record::field_value(ident, &seaorm_root);
                Ok(quote!((#name.to_owned(), #value)))
            })
            .collect::<syn::Result<Vec<_>>>()?;
        Ok(quote! {
            impl #core_root::entity::AuthRecordFields for #ident {
                fn field_values(&self) -> #core_root::AuthResult<#core_root::FieldMap> {
                    Ok(#core_root::FieldMap::from_iter([#(#values),*]))
                }
            }
        })
    })()
    .unwrap_or_else(syn::Error::into_compile_error);
    let implementation = match role {
        EntityRole::User => user_model::generate(
            (ident, fields),
            &aliases,
            &field_methods,
            (&seaorm_root, &core_root),
        )
        .unwrap_or_else(syn::Error::into_compile_error),
        EntityRole::Session => session_model::generate(
            (ident, fields),
            &aliases,
            &field_methods,
            (&seaorm_root, &core_root),
        )
        .unwrap_or_else(syn::Error::into_compile_error),
        role @ (EntityRole::Account | EntityRole::Verification) => {
            adapter_record::generate(input, fields, role, &seaorm_root, &core_root)
                .unwrap_or_else(syn::Error::into_compile_error)
        }
        _ if plugin_record => {
            plugin_model::generate(input, fields, &options, (&seaorm_root, &core_root))
                .unwrap_or_else(syn::Error::into_compile_error)
        }
        role => gen_organization_model(input, fields, role, &seaorm_root, &core_root)
            .unwrap_or_else(|error| error.to_compile_error()),
    };
    quote!(#record_fields #implementation)
}

struct EntityOptions {
    role: EntityRole,
    model_name: Option<LitStr>,
    row_presence: bool,
    native_passkey: bool,
    native_two_factor: bool,
}

fn parse_options(input: &DeriveInput) -> syn::Result<EntityOptions> {
    let mut parsed = None;
    let mut model_name = None;
    let mut row_presence = false;
    let mut native_passkey = false;
    let mut native_two_factor = false;
    for attr in &input.attrs {
        if !attr.path().is_ident("auth") {
            continue;
        }
        attr.parse_nested_meta(|meta| {
            if meta.path.is_ident("role") {
                let value = meta.value()?;
                let role: LitStr = value.parse()?;
                parsed = Some(match role.value().as_str() {
                    "user" => EntityRole::User,
                    "session" => EntityRole::Session,
                    "account" => EntityRole::Account,
                    "verification" => EntityRole::Verification,
                    "api_key" => EntityRole::ApiKey,
                    "device_code" => EntityRole::DeviceCode,
                    "passkey" => EntityRole::Passkey,
                    "two_factor" => EntityRole::TwoFactor,
                    "jwk" => EntityRole::Jwk,
                    "wallet_address" => EntityRole::WalletAddress,
                    "rate_limit" => EntityRole::RateLimit,
                    "organization" => EntityRole::Organization,
                    "member" => EntityRole::Member,
                    "invitation" => EntityRole::Invitation,
                    "team" => EntityRole::Team,
                    "team_member" => EntityRole::TeamMember,
                    "organization_role" => EntityRole::OrganizationRole,
                    _ => {
                        return Err(syn::Error::new_spanned(
                            role,
                            "unsupported auth role; use a core, organization, or supported plugin model role",
                        ));
                    }
                });
                Ok(())
            } else if meta.path.is_ident("row_presence") {
                row_presence = true;
                Ok(())
            } else if meta.path.is_ident("native_passkey") {
                native_passkey = true;
                Ok(())
            } else if meta.path.is_ident("native_two_factor") {
                native_two_factor = true;
                Ok(())
            } else if meta.path.is_ident("model_name") {
                model_name = Some(meta.value()?.parse::<LitStr>()?);
                Ok(())
            } else {
                Err(meta.error("expected `role = \"...\"`, `model_name = \"...\"`, `row_presence`, `native_passkey`, or `native_two_factor`"))
            }
        })?;
    }

    let role = parsed.ok_or_else(|| {
        syn::Error::new_spanned(
            input,
            "missing #[auth(role = \"...\")] attribute for AuthEntity",
        )
    })?;
    if role != EntityRole::RateLimit
        && let Some(name) = &model_name
    {
        return Err(syn::Error::new_spanned(
            name,
            "model_name is supported for the rate_limit role",
        ));
    }
    if row_presence && role != EntityRole::Session {
        return Err(syn::Error::new_spanned(
            input,
            "row_presence is supported for the session role",
        ));
    }
    if native_passkey && role != EntityRole::Passkey {
        return Err(syn::Error::new_spanned(
            input,
            "native_passkey is supported for the passkey role",
        ));
    }
    if native_two_factor && role != EntityRole::TwoFactor {
        return Err(syn::Error::new_spanned(
            input,
            "native_two_factor is supported for the two_factor role",
        ));
    }
    Ok(EntityOptions {
        role,
        model_name,
        row_presence,
        native_passkey,
        native_two_factor,
    })
}
