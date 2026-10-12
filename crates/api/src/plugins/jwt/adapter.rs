use super::{JwtCallbacks, JwtPlugin};
use crate::plugins::endpoint_context::EndpointContext;
use better_auth_core::{AuthResult, AuthSchema, CreateJwk, FieldValue, store::JwksStore};
use std::sync::Arc;

pub(super) fn store<'a, S: AuthSchema>(endpoint: &'a EndpointContext<'_, S>) -> &'a dyn JwksStore {
    match endpoint.transaction {
        Some(transaction) => transaction,
        None => endpoint.auth.database.as_ref(),
    }
}

pub(super) struct Keyring<'a, 'ctx, S: AuthSchema> {
    store: &'a dyn JwksStore,
    callbacks: Option<&'a JwtCallbacks<S>>,
    endpoint: &'a EndpointContext<'ctx, S>,
}

impl<'a, 'ctx, S: AuthSchema> Keyring<'a, 'ctx, S> {
    pub(super) fn new(
        store: &'a dyn JwksStore,
        callbacks: Option<&'a JwtCallbacks<S>>,
        endpoint: &'a EndpointContext<'ctx, S>,
    ) -> Self {
        Self {
            store,
            callbacks,
            endpoint,
        }
    }

    async fn find(&self, id: &str) -> AuthResult<FieldValue> {
        if let Some(callback) = self.callbacks.and_then(|callbacks| callbacks.get.as_ref()) {
            let keys = callback(self.endpoint).await?;
            if keys.is_null() || keys.is_undefined() {
                return Ok(FieldValue::Undefined);
            }
            return super::keys::find(&keys, id.into());
        }
        let key = self.store.get_jwk_value(&id.into()).await?;
        Ok(if key.is_null() {
            FieldValue::Undefined
        } else {
            key
        })
    }

    async fn all(&self) -> AuthResult<FieldValue> {
        if let Some(callback) = self.callbacks.and_then(|callbacks| callbacks.get.as_ref()) {
            return callback(self.endpoint).await;
        }
        self.store.list_jwk_values().await
    }

    pub(super) async fn latest(
        &self,
        algorithm: Option<&str>,
        default_algorithm: &str,
    ) -> AuthResult<FieldValue> {
        let before = algorithm
            .is_none()
            .then(|| chrono::Utc::now().timestamp_millis());
        let keys = self.all().await?;
        if algorithm.is_some() && !keys.is_truthy() {
            return Ok(FieldValue::Undefined);
        }
        let now = before.unwrap_or_else(|| chrono::Utc::now().timestamp_millis());
        super::keys::latest(keys, algorithm, default_algorithm, (now as f64).into())
    }
}

impl JwtPlugin {
    fn keyring<'a, 'ctx, S: AuthSchema>(
        &self,
        endpoint: &'a EndpointContext<'ctx, S>,
    ) -> Keyring<'a, 'ctx, S> {
        Keyring::new(
            store(endpoint),
            endpoint
                .auth
                .extensions
                .get::<Arc<JwtCallbacks<S>>>()
                .map(Arc::as_ref),
            endpoint,
        )
    }

    pub(super) async fn read_key<S: AuthSchema>(
        &self,
        id: &str,
        endpoint: &EndpointContext<'_, S>,
    ) -> AuthResult<FieldValue> {
        self.keyring(endpoint).find(id).await
    }

    pub(super) async fn read_keys<S: AuthSchema>(
        &self,
        endpoint: &EndpointContext<'_, S>,
    ) -> AuthResult<FieldValue> {
        self.keyring(endpoint).all().await
    }

    pub(super) async fn read_latest_key<S: AuthSchema>(
        &self,
        algorithm: Option<&str>,
        endpoint: &EndpointContext<'_, S>,
    ) -> AuthResult<FieldValue> {
        self.keyring(endpoint)
            .latest(algorithm, self.config.primary_algorithm().name())
            .await
    }

    pub(super) async fn persist_key<S: AuthSchema>(
        &self,
        mut data: CreateJwk,
        endpoint: &EndpointContext<'_, S>,
    ) -> AuthResult<FieldValue> {
        if let Some(callback) = endpoint
            .auth
            .extensions
            .get::<Arc<JwtCallbacks<S>>>()
            .and_then(|callbacks| callbacks.create.as_ref())
        {
            return callback(data, endpoint).await;
        }
        data.created_at = chrono::Utc::now().into();
        let mut fields = better_auth_core::FieldMap::from([("alg".into(), data.alg.into())]);
        if let Some(curve) = data.crv {
            let _ = fields.insert("crv".into(), curve.into());
        }
        fields.extend([
            ("publicKey".into(), data.public_key.into()),
            ("privateKey".into(), data.private_key.into()),
            ("createdAt".into(), data.created_at.into()),
        ]);
        if let Some(expiry) = data.expires_at {
            let _ = fields.insert("expiresAt".into(), expiry.into());
        }
        fields.extend(data.additional_fields);
        Ok(store(endpoint)
            .create_jwk_record(fields)
            .await?
            .map(FieldValue::from)
            .unwrap_or(FieldValue::Null))
    }
}
