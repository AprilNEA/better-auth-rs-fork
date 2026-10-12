use super::JwtPlugin;
use crate::plugins::endpoint_context::{EndpointContext, WithCallbacks};
use better_auth_core::{
    AuthPlugin, AuthRecordFields, AuthResult, AuthSchema, CreateJwk, FieldValue, Jwk,
};
use std::{future::Future, pin::Pin, sync::Arc};

/// A JWT adapter callback that borrows the active endpoint.
pub type JwtAdapterFuture<'a, T> = Pin<Box<dyn Future<Output = AuthResult<T>> + Send + 'a>>;
type Get<S> =
    dyn for<'a> Fn(&'a EndpointContext<'_, S>) -> JwtAdapterFuture<'a, FieldValue> + Send + Sync;
type Create<S> = dyn for<'a> Fn(CreateJwk, &'a EndpointContext<'_, S>) -> JwtAdapterFuture<'a, FieldValue>
    + Send
    + Sync;

/// Independent key reads and writes for one registered JWT plugin.
pub struct JwtCallbacks<S: AuthSchema> {
    pub(super) get: Option<Arc<Get<S>>>,
    pub(super) create: Option<Arc<Create<S>>>,
}

impl<S: AuthSchema> Default for JwtCallbacks<S> {
    fn default() -> Self {
        Self {
            get: None,
            create: None,
        }
    }
}

impl<S: AuthSchema> JwtCallbacks<S> {
    /// Read a custom keyring. `None` represents an absent keyset, not a database fallback.
    pub fn get_jwks<F>(self, callback: F) -> Self
    where
        F: for<'a> Fn(&'a EndpointContext<'_, S>) -> JwtAdapterFuture<'a, Option<Vec<Jwk>>>
            + Send
            + Sync
            + 'static,
    {
        self.get_jwks_native(move |endpoint| {
            let result = callback(endpoint);
            Box::pin(async move {
                Ok(match result.await? {
                    Some(keys) => keys
                        .iter()
                        .map(|key| key.field_values().map(FieldValue::from))
                        .collect::<AuthResult<Vec<_>>>()?
                        .into(),
                    None => FieldValue::Null,
                })
            })
        })
    }

    /// Read a native logical keyring, preserving array methods, accessors, and record identity.
    pub fn get_jwks_native<F>(mut self, callback: F) -> Self
    where
        F: for<'a> Fn(&'a EndpointContext<'_, S>) -> JwtAdapterFuture<'a, FieldValue>
            + Send
            + Sync
            + 'static,
    {
        self.get = Some(Arc::new(callback));
        self
    }

    /// Persist generated key material and return the nullable adapter readback.
    pub fn create_jwk<F>(self, callback: F) -> Self
    where
        F: for<'a> Fn(CreateJwk, &'a EndpointContext<'_, S>) -> JwtAdapterFuture<'a, Option<Jwk>>
            + Send
            + Sync
            + 'static,
    {
        self.create_jwk_native(move |data, endpoint| {
            let result = callback(data, endpoint);
            Box::pin(async move {
                Ok(match result.await? {
                    Some(key) => key.field_values()?.into(),
                    None => FieldValue::Null,
                })
            })
        })
    }

    /// Persist generated material and retain the native logical adapter readback.
    pub fn create_jwk_native<F>(mut self, callback: F) -> Self
    where
        F: for<'a> Fn(CreateJwk, &'a EndpointContext<'_, S>) -> JwtAdapterFuture<'a, FieldValue>
            + Send
            + Sync
            + 'static,
    {
        self.create = Some(Arc::new(callback));
        self
    }
}

impl JwtPlugin {
    /// Attach schema-aware key adapter callbacks after configuring plugin options.
    pub fn callbacks<S: AuthSchema>(self, callbacks: JwtCallbacks<S>) -> impl AuthPlugin<S> {
        WithCallbacks {
            plugin: self,
            callbacks: Arc::new(callbacks),
        }
    }
}
