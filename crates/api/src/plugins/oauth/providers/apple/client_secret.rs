//! Sign in with Apple client-secret generation.
//!
//! Apple's token endpoint accepts an ES256 JWT as the OAuth `client_secret`.
//! [`AppleClientSecretSigner`] signs that JWT with the developer's private key
//! and renews it before it expires, so applications do not rotate a static
//! secret by hand.

use std::fmt;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use better_auth_core::{AuthError, AuthResult};
use josekit::JoseError;
use josekit::jws::alg::ecdsa::EcdsaJwsSigner;
use josekit::jws::{ES256, JwsHeader};
use josekit::jwt::{self, JwtPayload};
use serde_json::{Map, Value};

const AUDIENCE: &str = "https://appleid.apple.com";
/// Apple rejects client secrets that expire more than 15,777,000 seconds after issue.
const MAX_LIFETIME_SECS: i64 = 15_777_000;
/// The shortest lifetime keeps every secret usable beyond the renewal margin.
const MIN_LIFETIME_SECS: i64 = 600;
const DEFAULT_LIFETIME_SECS: i64 = 3600;
/// A cached secret is renewed when less than this many seconds remain.
const RENEWAL_MARGIN_SECS: i64 = 300;

/// Rejected Sign in with Apple client-secret configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum AppleClientSecretError {
    /// The Apple Developer Team ID is empty.
    #[error("Apple team ID must not be empty")]
    MissingTeamId,
    /// The Sign in with Apple key ID is empty.
    #[error("Apple key ID must not be empty")]
    MissingKeyId,
    /// The private key is not a PKCS #8 PEM key that can sign ES256.
    #[error("Apple private key must be a PKCS #8 PEM key for ES256")]
    InvalidPrivateKey,
    /// The requested lifetime is outside the range that Apple accepts.
    #[error("Apple client secret lifetime must be between 600 and 15777000 seconds")]
    InvalidLifetime,
}

/// Generates and renews Sign in with Apple client secrets.
///
/// Each secret is an ES256 JWT with the Team ID as `iss`, the OAuth client ID
/// as `sub`, and `https://appleid.apple.com` as `aud`. Secrets last one hour by
/// default. A cached secret is reused until less than five minutes remain.
/// Clones share the same cache.
#[derive(Clone)]
pub struct AppleClientSecretSigner {
    inner: Arc<Signer>,
}

struct Signer {
    team_id: String,
    key_id: String,
    key: EcdsaJwsSigner,
    lifetime_secs: i64,
    cache: Mutex<Option<CachedSecret>>,
}

struct CachedSecret {
    client_id: String,
    value: String,
    issued_at: i64,
    expires_at: i64,
}

impl AppleClientSecretSigner {
    /// Create a signer from the Team ID, the key ID, and the `.p8` private key.
    ///
    /// `private_key_pem` is the PKCS #8 PEM file that Apple issues for a
    /// Sign in with Apple key. The key is checked with a trial signature.
    pub fn new(
        team_id: &str,
        key_id: &str,
        private_key_pem: &[u8],
    ) -> Result<Self, AppleClientSecretError> {
        let team_id = team_id.trim();
        if team_id.is_empty() {
            return Err(AppleClientSecretError::MissingTeamId);
        }
        let key_id = key_id.trim();
        if key_id.is_empty() {
            return Err(AppleClientSecretError::MissingKeyId);
        }
        // Loading checks the PEM structure and requires the P-256 curve.
        let key = ES256
            .signer_from_pem(private_key_pem)
            .map_err(|_| AppleClientSecretError::InvalidPrivateKey)?;
        Signer::new(
            team_id.to_owned(),
            key_id.to_owned(),
            key,
            DEFAULT_LIFETIME_SECS,
        )
        .map(|signer| Self {
            inner: Arc::new(signer),
        })
    }

    /// Return a signer whose secrets remain valid for `lifetime`.
    ///
    /// The lifetime must be between 10 minutes and 15,777,000 seconds (about
    /// six months). Fractions of a second are ignored. The returned signer
    /// starts with an empty cache.
    pub fn with_lifetime(self, lifetime: Duration) -> Result<Self, AppleClientSecretError> {
        let lifetime_secs = i64::try_from(lifetime.as_secs())
            .ok()
            .filter(|seconds| (MIN_LIFETIME_SECS..=MAX_LIFETIME_SECS).contains(seconds))
            .ok_or(AppleClientSecretError::InvalidLifetime)?;
        let signer = Signer::new(
            self.inner.team_id.clone(),
            self.inner.key_id.clone(),
            self.inner.key.clone(),
            lifetime_secs,
        )?;
        Ok(Self {
            inner: Arc::new(signer),
        })
    }

    /// Return a valid client secret for `client_id`.
    ///
    /// The signer reuses its cached secret for the same client ID until less
    /// than five minutes of validity remain. Otherwise it signs a new secret.
    pub fn client_secret(&self, client_id: &str) -> AuthResult<String> {
        self.client_secret_at(client_id, chrono::Utc::now().timestamp())
    }

    pub(in crate::plugins::oauth) fn client_secret_at(
        &self,
        client_id: &str,
        now: i64,
    ) -> AuthResult<String> {
        let mut cache = self
            .inner
            .cache
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if let Some(cached) = cache.as_ref().filter(|cached| {
            cached.client_id == client_id
                && cached.issued_at <= now
                && cached.expires_at - now > RENEWAL_MARGIN_SECS
        }) {
            return Ok(cached.value.clone());
        }
        let value = self
            .inner
            .sign(client_id, now)
            .map_err(|_| AuthError::internal("Failed to sign the Apple client secret"))?;
        *cache = Some(CachedSecret {
            client_id: client_id.to_owned(),
            value: value.clone(),
            issued_at: now,
            expires_at: now + self.inner.lifetime_secs,
        });
        Ok(value)
    }
}

impl fmt::Debug for AppleClientSecretSigner {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AppleClientSecretSigner")
            .field("team_id", &self.inner.team_id)
            .field("key_id", &self.inner.key_id)
            .field("lifetime_secs", &self.inner.lifetime_secs)
            .finish_non_exhaustive()
    }
}

impl Signer {
    fn new(
        team_id: String,
        key_id: String,
        key: EcdsaJwsSigner,
        lifetime_secs: i64,
    ) -> Result<Self, AppleClientSecretError> {
        let signer = Self {
            team_id,
            key_id,
            key,
            lifetime_secs,
            cache: Mutex::new(None),
        };
        // A trial signature proves that the loaded key can sign ES256.
        let _ = signer
            .sign("key-check", 0)
            .map_err(|_| AppleClientSecretError::InvalidPrivateKey)?;
        Ok(signer)
    }

    fn sign(&self, client_id: &str, issued_at: i64) -> Result<String, JoseError> {
        // Apple documents a header with only `alg` and `kid`.
        let mut header = JwsHeader::new();
        header.set_key_id(&self.key_id);
        let mut claims = Map::new();
        let _ = claims.insert("iss".into(), Value::from(self.team_id.as_str()));
        let _ = claims.insert("iat".into(), Value::from(issued_at));
        let _ = claims.insert("exp".into(), Value::from(issued_at + self.lifetime_secs));
        let _ = claims.insert("aud".into(), Value::from(AUDIENCE));
        let _ = claims.insert("sub".into(), Value::from(client_id));
        let payload = JwtPayload::from_map(claims)?;
        jwt::encode_with_signer(&payload, &header, &self.key)
    }
}
