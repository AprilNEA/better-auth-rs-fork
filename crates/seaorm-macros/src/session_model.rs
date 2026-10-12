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
    let user_id = bindings.ident("user_id")?;
    let user_id_type = &bindings.require("user_id")?.ty;
    let id_view = identity::string_view(id_type, &id.to_string());
    let user_id_view = if identity::is_reference(EntityRole::Session, bindings.require("user_id")?)?
    {
        if identity::optional_inner(user_id_type).is_some() {
            quote!(match &self.#user_id {
                Some(value) => #core::SchemaValue::Typed(::std::borrow::Cow::Owned(value.to_string())),
                None => #core::SchemaValue::from_field(#core::FieldValue::Null),
            })
        } else {
            let view = identity::string_view(user_id_type, &user_id.to_string());
            quote!(#core::SchemaValue::Typed(#view))
        }
    } else {
        quote!(#core::SchemaValue::from_field(#core::SchemaField::into_field(&self.#user_id)))
    };
    let native_fields = [
        "token",
        "expires_at",
        "created_at",
        "updated_at",
        "ip_address",
        "user_agent",
        "impersonated_by",
        "active_organization_id",
        "active_team_id",
    ];
    let updates = native_fields
        .into_iter()
        .filter(|name| bindings.get(name).is_some())
        .map(|name| {
            let field = format_ident!("{name}");
            let assignment = bindings.assignment(name, EntityRole::Session, seaorm, core)?;
            Ok(quote! {
                if let Some(value) = update.#field {
                    let value = #core::SchemaField::into_field(value);
                    #assignment
                }
            })
        })
        .collect::<syn::Result<Vec<_>>>()?;
    let getters = native_fields.into_iter().map(|name| {
        let method = format_ident!("{name}");
        let ty = match name {
            "expires_at" | "created_at" | "updated_at" => quote!(#core::FieldDate),
            "token" => quote!(::std::borrow::Cow<'_, str>),
            _ => quote!(Option<::std::borrow::Cow<'_, str>>),
        };
        let value = match bindings.get(name).and_then(|field| field.ident.as_ref()) {
            Some(field) => {
                quote!(#core::SchemaValue::from_field(#core::SchemaField::into_field(&self.#field)))
            }
            None => quote!(#core::SchemaValue::Typed(None)),
        };
        quote!(fn #method(&self) -> #core::SchemaValue<#ty> { #value })
    });
    let plugin_fields: Vec<_> = registry::plugin_field_names(EntityRole::Session)
        .into_iter()
        .filter(|name| bindings.get(name).is_some())
        .collect();
    let columns = ["id", "token", "user_id", "expires_at", "created_at"]
        .into_iter()
        .map(|name| {
            let method = format_ident!("{name}_column");
            let column = bindings.column(name)?;
            Ok(quote!(fn #method() -> Self::Column { Column::#column }))
        })
        .collect::<syn::Result<Vec<_>>>()?;
    let (active_value, active_column, active_insert) = match bindings.get("active") {
        Some(_) => {
            let field = bindings.ident("active")?;
            let column = bindings.column("active")?;
            (
                quote!(self.#field),
                quote!(Some(Column::#column)),
                quote!(#field: #seaorm::sea_orm::ActiveValue::Set(true),),
            )
        }
        None => (quote!(true), quote!(None), TokenStream::new()),
    };
    let setters = [
        "expires_at",
        "updated_at",
        "active_organization_id",
        "active_team_id",
    ]
    .into_iter()
    .map(|name| {
        let method = format_ident!("set_{name}");
        let ty = if matches!(name, "expires_at" | "updated_at") {
            quote!(#seaorm::sea_orm::entity::prelude::DateTimeUtc)
        } else {
            quote!(Option<String>)
        };
        let body = if bindings.get(name).is_some() {
            let assignment = bindings.assignment(name, EntityRole::Session, seaorm, core)?;
            quote! { let value = #core::SchemaField::into_field(value); #assignment }
        } else {
            quote!(let _ = (active, value);)
        };
        Ok(quote! {
            fn #method(active: &mut Self::ActiveModel, value: #ty) -> #core::AuthResult<()> {
                #body
                Ok(())
            }
        })
    })
    .collect::<syn::Result<Vec<_>>>()?;
    let user_id_parse = identity::parse_user_id(
        bindings.require("user_id")?,
        "Invalid session user id",
        core,
        seaorm,
    );
    Ok(quote! {
        impl #core::entity::AuthSession for #ident {
            #aliases
            const PLUGIN_FIELDS: &'static [&'static str] = &[#(#plugin_fields),*];
            fn id(&self) -> #core::SchemaValue<::std::borrow::Cow<'_, str>> { #core::SchemaValue::Typed(#id_view) }
            #(#getters)*
            fn user_id(&self) -> #core::SchemaValue<::std::borrow::Cow<'_, str>> { #user_id_view }
            fn active(&self) -> bool { #active_value }
        }
        impl #seaorm::SeaOrmSessionModel for #ident {
            #field_methods
            type Id = #id_type;
            type UserId = #user_id_type;
            type Entity = Entity;
            type ActiveModel = ActiveModel;
            type Column = Column;
            #(#columns)*
            fn active_column() -> Option<Self::Column> { #active_column }
            fn parse_id(id: &str) -> #core::AuthResult<Self::Id> {
                id.parse().map_err(|error| #core::AuthError::bad_request(format!("Invalid session id: {error}")))
            }
            fn parse_user_id(value: &str) -> #core::AuthResult<Self::UserId> {
                #user_id_parse
            }
            fn new_active(id: Option<Self::Id>, _fields: &#core::FieldMap) -> #core::AuthResult<Self::ActiveModel> {
                Ok(Self::ActiveModel {
                    #id: id.map_or(#seaorm::sea_orm::ActiveValue::NotSet, #seaorm::sea_orm::ActiveValue::Set),
                    #active_insert
                    ..Default::default()
                })
            }
            fn apply_update(active: &mut Self::ActiveModel, update: #seaorm::SessionUpdate) -> #core::AuthResult<()> {
                if let Some(id) = update.id { active.#id = #seaorm::sea_orm::ActiveValue::Set(Self::parse_id(&id)?); }
                if let Some(id) = update.user_id { active.#user_id = #seaorm::sea_orm::ActiveValue::Set(Self::parse_user_id(&id)?); }
                #(#updates)*
                Ok(())
            }
            #(#setters)*
        }
    })
}
