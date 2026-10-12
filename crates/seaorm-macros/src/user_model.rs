use super::*;

pub(super) fn generate(
    model: (&Ident, &syn::FieldsNamed),
    aliases: &TokenStream,
    field_methods: &TokenStream,
    (seaorm, core): (&TokenStream, &TokenStream),
) -> syn::Result<TokenStream> {
    let (ident, fields) = model;
    let bindings = field_bindings::FieldBindings::new(fields)?;
    let id = bindings.ident("id")?;
    let id_type = &bindings.require("id")?.ty;
    let id_view = identity::string_view(id_type, &id.to_string());
    let plugin_fields: Vec<_> = registry::plugin_field_names(EntityRole::User)
        .into_iter()
        .filter(|name| bindings.get(name).is_some())
        .collect();
    let getters = [
        "email",
        "email_verified",
        "created_at",
        "updated_at",
        "is_anonymous",
        "phone_number",
        "phone_number_verified",
        "username",
        "display_username",
        "two_factor_enabled",
        "role",
        "banned",
        "ban_reason",
        "ban_expires",
    ]
    .into_iter()
    .map(|name| {
        let method = format_ident!("{name}");
        let ty = match name {
            "email_verified" | "banned" => quote!(bool),
            "created_at" | "updated_at" => quote!(#core::FieldDate),
            "ban_expires" => quote!(Option<#core::FieldDate>),
            "is_anonymous" | "phone_number_verified" | "two_factor_enabled" => quote!(Option<bool>),
            _ => quote!(Option<::std::borrow::Cow<'_, str>>),
        };
        let value = match bindings.get(name).and_then(|field| field.ident.as_ref()) {
            Some(field) => {
                quote!(#core::SchemaValue::from_field(#core::SchemaField::into_field(&self.#field)))
            }
            None => quote!(#core::SchemaValue::Undefined),
        };
        quote!(fn #method(&self) -> #core::SchemaValue<#ty> { #value })
    });
    let columns = ["id", "email", "name", "created_at"]
        .into_iter()
        .map(|name| {
            let method = format_ident!("{name}_column");
            let column = bindings.column(name)?;
            Ok(quote!(fn #method() -> Self::Column { Column::#column }))
        })
        .collect::<syn::Result<Vec<_>>>()?;
    let optional_columns = ["phone_number", "username"]
        .into_iter()
        .map(|name| {
            let method = format_ident!("{name}_column");
            let column = bindings
                .get(name)
                .map(|_| bindings.column(name))
                .transpose()?;
            let value = column.map_or_else(|| quote!(None), |column| quote!(Some(Column::#column)));
            Ok(quote!(fn #method() -> Option<Self::Column> { #value }))
        })
        .collect::<syn::Result<Vec<_>>>()?;

    let create = [
        ("email", quote!(create_user.email)),
        ("name", quote!(create_user.name)),
        ("image", quote!(create_user.image)),
        (
            "email_verified",
            quote!(create_user.email_verified.unwrap_or(false)),
        ),
        ("created_at", quote!(now)),
        ("updated_at", quote!(now)),
        ("is_anonymous", quote!(create_user.is_anonymous)),
        ("phone_number", quote!(create_user.phone_number)),
        (
            "phone_number_verified",
            quote!(create_user.phone_number_verified),
        ),
        ("username", quote!(create_user.username.flatten())),
        (
            "display_username",
            quote!(create_user.display_username.flatten()),
        ),
        ("two_factor_enabled", quote!(false)),
        ("role", quote!(create_user.role)),
        ("banned", quote!(create_user.banned.unwrap_or(false))),
        ("ban_reason", quote!(create_user.ban_reason)),
        ("ban_expires", quote!(create_user.ban_expires)),
        (
            "metadata",
            quote!(create_user.metadata.unwrap_or_else(|| #core::FieldMap::new().into())),
        ),
    ]
    .into_iter()
    .filter(|(name, _)| bindings.get(name).is_some())
    .map(|(name, value)| {
        let assignment = bindings.assignment(name, EntityRole::User, seaorm, core)?;
        Ok(quote! {
            let value = #core::SchemaField::into_field(#value);
            if !value.is_undefined() { #assignment }
        })
    })
    .collect::<syn::Result<Vec<_>>>()?;

    let mut updates = Vec::new();
    for name in ["name", "image"] {
        let field = format_ident!("{name}");
        let assignment = bindings.assignment(name, EntityRole::User, seaorm, core)?;
        updates.push(quote! {
            let value = #core::SchemaField::into_field(update.#field);
            if !value.is_undefined() { #assignment }
        });
    }
    for name in [
        "email",
        "email_verified",
        "is_anonymous",
        "phone_number_verified",
        "phone_number",
        "username",
        "display_username",
        "role",
        "two_factor_enabled",
        "metadata",
        "banned",
        "ban_reason",
        "ban_expires",
    ] {
        if bindings.get(name).is_some() {
            let field = format_ident!("{name}");
            let assignment = bindings.assignment(name, EntityRole::User, seaorm, core)?;
            updates.push(quote! {
                if let Some(value) = update.#field {
                    let value = #core::SchemaField::into_field(value);
                    #assignment
                }
            });
        }
    }
    let update_date = bindings.assignment("updated_at", EntityRole::User, seaorm, core)?;

    Ok(quote! {
        impl #core::entity::AuthUser for #ident {
            #aliases
            const PLUGIN_FIELDS: &'static [&'static str] = &[#(#plugin_fields),*];
            fn id(&self) -> #core::SchemaValue<::std::borrow::Cow<'_, str>> { #core::SchemaValue::Typed(#id_view) }
            #(#getters)*
        }
        impl #seaorm::SeaOrmUserModel for #ident {
            #field_methods
            type Id = #id_type;
            type Entity = Entity;
            type ActiveModel = ActiveModel;
            type Column = Column;
            #(#columns)*
            #(#optional_columns)*
            fn parse_id(id: &str) -> #core::AuthResult<Self::Id> {
                id.parse().map_err(|error| #core::AuthError::bad_request(format!("Invalid user id: {error}")))
            }
            fn new_active(
                id: Option<Self::Id>,
                create_user: #core::types::CreateUser,
                now: #seaorm::sea_orm::entity::prelude::DateTimeUtc,
            ) -> #core::AuthResult<Self::ActiveModel> {
                let mut active = Self::ActiveModel {
                    #id: id.map_or(#seaorm::sea_orm::ActiveValue::NotSet, #seaorm::sea_orm::ActiveValue::Set),
                    ..Default::default()
                };
                #(#create)*
                Ok(active)
            }
            fn apply_update(
                active: &mut Self::ActiveModel,
                update: #core::types::UpdateUser,
                now: #seaorm::sea_orm::entity::prelude::DateTimeUtc,
            ) -> #core::AuthResult<()> {
                #(#updates)*
                let value = #core::SchemaField::into_field(now);
                #update_date
                Ok(())
            }
        }
    })
}
