use std::{collections::HashSet, path::PathBuf};

use proc_macro2::{Group, TokenStream, TokenTree};
use quote::{ToTokens, quote};
use syn::{FnArg, ImplItem, Item, ItemImpl, LitStr, Pat, TraitItem};

pub(crate) fn expand(source: LitStr, implementation: ItemImpl) -> TokenStream {
    match forward(&source, implementation) {
        Ok(tokens) => tokens,
        Err(error) => error.into_compile_error(),
    }
}

fn forward(source: &LitStr, mut implementation: ItemImpl) -> syn::Result<TokenStream> {
    let (_, trait_path, _) = implementation.trait_.as_ref().ok_or_else(|| {
        syn::Error::new_spanned(
            &implementation.self_ty,
            "Expected a Store trait implementation",
        )
    })?;
    let trait_name = &trait_path
        .segments
        .last()
        .ok_or_else(|| syn::Error::new_spanned(trait_path, "Expected a Store trait path"))?
        .ident;
    let manifest = std::env::var_os("CARGO_MANIFEST_DIR")
        .ok_or_else(|| syn::Error::new_spanned(source, "CARGO_MANIFEST_DIR is unavailable"))?;
    let path = PathBuf::from(manifest).join(source.value());
    let text = std::fs::read_to_string(&path).map_err(|error| {
        syn::Error::new_spanned(source, format!("Cannot read {}: {error}", path.display()))
    })?;
    let declaration = syn::parse_file(&text)?
        .items
        .into_iter()
        .find_map(|item| match item {
            Item::Trait(item) if item.ident == *trait_name => Some(item),
            _ => None,
        })
        .ok_or_else(|| {
            syn::Error::new_spanned(source, format!("Cannot find trait {trait_name}"))
        })?;
    let overrides: HashSet<_> = implementation
        .items
        .iter()
        .filter_map(|item| match item {
            ImplItem::Fn(method) => Some(method.sig.ident.to_string()),
            _ => None,
        })
        .collect();
    let mut asynchronous = false;
    for item in declaration.items {
        let TraitItem::Fn(method) = item else {
            return Err(syn::Error::new_spanned(
                item,
                "Store forwarding supports method declarations only",
            ));
        };
        asynchronous |= method.sig.asyncness.is_some();
        if overrides.contains(&method.sig.ident.to_string()) {
            continue;
        }
        let mut arguments = Vec::new();
        for input in &method.sig.inputs {
            match input {
                FnArg::Receiver(receiver) if receiver.reference.is_some() => {}
                FnArg::Typed(argument) => match argument.pat.as_ref() {
                    Pat::Ident(binding) if binding.subpat.is_none() => {
                        arguments.push(binding.ident.clone());
                    }
                    pattern => {
                        return Err(syn::Error::new_spanned(
                            pattern,
                            "Store forwarding requires named arguments",
                        ));
                    }
                },
                input => {
                    return Err(syn::Error::new_spanned(
                        input,
                        "Store forwarding requires a borrowed receiver",
                    ));
                }
            }
        }
        let name = &method.sig.ident;
        let signature = qualify_store_paths(method.sig.to_token_stream());
        let await_result = method.sig.asyncness.map(|_| quote!(.await));
        let attributes = method
            .attrs
            .iter()
            .filter(|attribute| !attribute.path().is_ident("doc"));
        implementation.items.push(syn::parse2(quote! {
            #(#attributes)*
            #signature {
                self.inner.#name(#(#arguments),*) #await_result
            }
        })?);
    }
    let tracked_source = LitStr::new(
        path.to_str().ok_or_else(|| {
            syn::Error::new_spanned(source, "Store source paths must contain valid UTF-8")
        })?,
        source.span(),
    );
    let asynchronous =
        asynchronous.then(|| quote!(#[::better_auth_core::__private_async_trait::async_trait]));
    Ok(quote! {
        const _: &str = include_str!(#tracked_source);
        #asynchronous
        #implementation
    })
}

// Store signatures are declared in core::store or its runtime child module.
// Qualify only path roots; argument names and nested token groups retain their syntax.
fn qualify_store_paths(tokens: TokenStream) -> TokenStream {
    let mut qualified = TokenStream::new();
    let mut tokens = tokens.into_iter().peekable();
    while let Some(token) = tokens.next() {
        match token {
            TokenTree::Group(group) => {
                let mut replacement =
                    Group::new(group.delimiter(), qualify_store_paths(group.stream()));
                replacement.set_span(group.span());
                qualified.extend([TokenTree::Group(replacement)]);
            }
            TokenTree::Ident(root) if matches!(tokens.peek(), Some(TokenTree::Punct(punctuation)) if punctuation.as_char() == ':') => {
                match root.to_string().as_str() {
                    "crate" => qualified.extend(quote!(::better_auth_core)),
                    "super" => qualified.extend(quote!(::better_auth_core::store)),
                    _ => qualified.extend([TokenTree::Ident(root)]),
                }
            }
            token => qualified.extend([token]),
        }
    }
    qualified
}
