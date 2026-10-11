//! Persisted signing keys for the JWT plugin.

use crate::SchemaValue;

/// A persisted signing key. Private key material must never enter an HTTP response.
#[derive(Clone, Default)]
pub struct Jwk {
    /// Source property order, independent of the current typed values.
    pub field_order: Vec<String>,
    /// Stable identifier used by the JWT `kid` header.
    pub id: SchemaValue<String>,
    /// Serialized public JWK.
    pub public_key: SchemaValue<String>,
    /// Serialized private JWK, encrypted unless explicitly configured otherwise.
    pub private_key: SchemaValue<String>,
    /// Creation time used to select the newest live key.
    pub created_at: SchemaValue<crate::FieldDate>,
    /// Time after which this key stops signing new tokens.
    pub expires_at: SchemaValue<Option<crate::FieldDate>>,
    /// Signing algorithm; absent on legacy rows.
    pub alg: SchemaValue<Option<String>>,
    /// Elliptic curve identifier, when applicable.
    pub crv: SchemaValue<Option<String>>,
    /// Declared application fields returned by the adapter; excluded from public JWKS discovery.
    pub additional_fields: crate::FieldMap,
}

impl PartialEq for Jwk {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id
            && self.public_key == other.public_key
            && self.private_key == other.private_key
            && self.created_at == other.created_at
            && self.expires_at == other.expires_at
            && self.alg == other.alg
            && self.crv == other.crv
            && self.additional_fields == other.additional_fields
    }
}

/// Key material to persist after generation.
pub struct CreateJwk {
    /// Generation time supplied to a custom key-persistence callback.
    pub created_at: crate::FieldDate,
    /// Serialized public JWK.
    pub public_key: String,
    /// Serialized or encrypted private JWK.
    pub private_key: String,
    /// Signing expiration time.
    pub expires_at: Option<crate::FieldDate>,
    /// Signing algorithm.
    pub alg: String,
    /// Elliptic curve identifier, when applicable.
    pub crv: Option<String>,
    /// Logical application fields consumed by registered adapter policies.
    pub additional_fields: crate::FieldMap,
}
