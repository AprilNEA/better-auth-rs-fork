use crate::{AuthConfig, AuthRequest, AuthResult, AuthSchema, FieldMap, store::AuthTransaction};
use serde_json::{Map, Value};

/// The active request and storage transaction for a session-cache signature.
pub struct SessionCookieContext<'a, S: AuthSchema> {
    pub request: &'a AuthRequest,
    pub config: &'a AuthConfig,
    /// Read and create signing keys through this transaction when present.
    pub transaction: Option<&'a dyn AuthTransaction<S>>,
}

/// Runtime boundary for plugins that sign and verify session cookie caches.
#[async_trait::async_trait]
pub trait SessionCookieSigner<S: AuthSchema>: Send + Sync {
    /// Sign native cache claims with the lifetime in seconds, preserving fractional seconds.
    /// Keep native values until the signer's clone or serialization boundary.
    async fn sign(
        &self,
        payload: FieldMap,
        expires_in: f64,
        context: SessionCookieContext<'_, S>,
    ) -> AuthResult<String>;
    /// Return verified cache claims, or `None` for an invalid token.
    async fn verify(
        &self,
        token: &str,
        context: SessionCookieContext<'_, S>,
    ) -> AuthResult<Option<Map<String, Value>>>;
}
