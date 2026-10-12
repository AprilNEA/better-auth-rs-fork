use crate::SchemaValue;
use std::borrow::Cow;

use crate::entity::{AuthApiKey, AuthPasskey, AuthTwoFactor};

/// Two-factor authentication response shape.
#[derive(Debug, Clone, Default)]
pub struct TwoFactor {
    /// Source property order, independent of the current typed values.
    pub field_order: Vec<String>,
    pub id: SchemaValue<String>,
    pub secret: SchemaValue<String>,
    pub backup_codes: SchemaValue<String>,
    pub user_id: SchemaValue<String>,
    /// Whether the authenticator secret has completed enrollment.
    pub verified: SchemaValue<Option<bool>>,
    /// Consecutive failed sign-in verifications across factors and challenges.
    pub failed_verification_count: SchemaValue<Option<f64>>,
    /// End of the account-level verification lock.
    pub locked_until: SchemaValue<Option<crate::FieldDate>>,
    pub created_at: SchemaValue<crate::FieldDate>,
    pub updated_at: SchemaValue<crate::FieldDate>,
    /// Declared application fields after adapter output projection.
    pub additional_fields: crate::FieldMap,
}

impl PartialEq for TwoFactor {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id
            && self.secret == other.secret
            && self.backup_codes == other.backup_codes
            && self.user_id == other.user_id
            && self.verified == other.verified
            && self.failed_verification_count == other.failed_verification_count
            && self.locked_until == other.locked_until
            && self.created_at == other.created_at
            && self.updated_at == other.updated_at
            && self.additional_fields == other.additional_fields
    }
}

/// Two-factor persistence representation selected by the model.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TwoFactorStorage {
    /// Store the upstream columns without creation or update timestamps.
    Native,
    /// Preserve the legacy creation and update timestamps.
    Legacy,
}

/// Two-factor authentication creation data.
#[derive(Debug, Clone)]
pub struct CreateTwoFactor {
    /// Declared application fields before adapter input policies.
    pub additional_fields: crate::FieldMap,
    pub user_id: String,
    pub secret: String,
    pub backup_codes: String,
    /// Whether enrollment verification may be skipped.
    pub verified: bool,
}

/// Fields changed when an existing authenticator enrollment is completed or replaced.
#[derive(Debug, Default)]
pub struct UpdateTwoFactor {
    /// Declared application fields to update; omitted keys retain their stored values.
    pub additional_fields: crate::FieldMap,
    /// Replacement encrypted authenticator secret.
    pub secret: Option<String>,
    /// Replacement encrypted backup codes.
    pub backup_codes: Option<String>,
    /// Enrollment verification state.
    pub verified: Option<bool>,
}

/// Passkey persistence representation selected by the store.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PasskeyStorage {
    /// Store the upstream standard columns without an opaque credential envelope.
    Native,
    /// Preserve the opaque credential envelope and the legacy update timestamp.
    Legacy,
}

/// Credential state supplied when creating a passkey.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PasskeyCredentialState {
    /// The standard columns contain the credential state.
    Native,
    /// Preserve these opaque bytes in the legacy credential column.
    Legacy(String),
}

impl From<String> for PasskeyCredentialState {
    fn from(value: String) -> Self {
        Self::Legacy(value)
    }
}

impl From<&str> for PasskeyCredentialState {
    fn from(value: &str) -> Self {
        Self::Legacy(value.to_owned())
    }
}

/// Passkey response shape.
#[derive(Debug, Clone)]
pub struct Passkey {
    /// Source property order, independent of the current typed values.
    pub field_order: Vec<String>,
    /// Declared application fields after adapter output projection.
    pub additional_fields: crate::FieldMap,
    pub id: SchemaValue<String>,
    pub name: SchemaValue<Option<String>>,
    pub public_key: SchemaValue<String>,
    pub user_id: SchemaValue<String>,
    pub credential_id: SchemaValue<String>,
    pub counter: SchemaValue<u64>,
    pub device_type: SchemaValue<String>,
    pub backed_up: SchemaValue<bool>,
    pub transports: SchemaValue<Option<String>>,
    pub created_at: SchemaValue<Option<crate::FieldDate>>,
    pub updated_at: SchemaValue<crate::FieldDate>,
    pub aaguid: SchemaValue<Option<String>>,
    pub credential: SchemaValue<String>,
}

impl PartialEq for Passkey {
    fn eq(&self, other: &Self) -> bool {
        self.additional_fields == other.additional_fields
            && self.id == other.id
            && self.name == other.name
            && self.public_key == other.public_key
            && self.user_id == other.user_id
            && self.credential_id == other.credential_id
            && self.counter == other.counter
            && self.device_type == other.device_type
            && self.backed_up == other.backed_up
            && self.transports == other.transports
            && self.created_at == other.created_at
            && self.updated_at == other.updated_at
            && self.aaguid == other.aaguid
            && self.credential == other.credential
    }
}

/// Input for creating a new passkey.
#[derive(Debug, Clone)]
pub struct CreatePasskey {
    /// Declared application fields before adapter input policies.
    pub additional_fields: crate::FieldMap,
    pub user_id: SchemaValue<String>,
    /// Omission and explicit null remain distinct during field input transforms.
    pub name: SchemaValue<Option<String>>,
    pub credential_id: String,
    pub public_key: String,
    pub counter: u64,
    pub device_type: String,
    pub backed_up: bool,
    pub transports: Option<String>,
    pub credential: PasskeyCredentialState,
    /// Omission and explicit null remain distinct during field input transforms.
    pub aaguid: SchemaValue<Option<String>>,
}

/// Display fields and counter changed by one passkey adapter update.
#[derive(Debug, Clone, Default)]
pub struct UpdatePasskey {
    /// Omitted values retain the stored name unless an update policy supplies a value.
    pub name: SchemaValue<Option<String>>,
    /// Omitted values retain the stored AAGUID unless an update policy supplies a value.
    pub aaguid: SchemaValue<Option<String>>,
    /// Declared application fields before adapter input policies.
    pub additional_fields: crate::FieldMap,
    /// Replace the stored authenticator counter when supplied.
    pub counter: Option<u64>,
}

/// Input for updating stored passkey credential state after authentication.
#[derive(Debug, Clone)]
pub enum UpdatePasskeyAuthentication {
    /// Update only the counter in an upstream standard record.
    Native { counter: u64 },
    /// Preserve the legacy opaque credential and metadata update contract.
    Legacy {
        credential: String,
        counter: u64,
        backed_up: bool,
        device_type: String,
    },
}

mod device;
pub use device::DeviceCode;

/// Issuer ownership required by atomic device-code consumption.
#[derive(Debug, Clone, PartialEq)]
pub enum DeviceCodeOwnership {
    /// Require the stored client binding to equal this client identifier.
    ClientId(String),
    /// Match a declared field through the selected adapter's query conversions.
    /// This condition uses `eq`, `AND`, and case-sensitive comparison.
    /// Other connectors are not supported by this variant.
    FieldEquals {
        /// A registered logical field name or configured storage field name.
        field: String,
        /// Native query value, preserving object identity until adapter conversion.
        value: crate::FieldValue,
    },
    /// Require membership in a candidate set with `AND` and case-sensitive comparison.
    FieldIn {
        /// A registered logical field name or configured storage field name.
        field: String,
        /// Native candidates converted by the selected adapter.
        /// An empty set does not match in Memory or SQLite and produces a PostgreSQL or MySQL syntax error.
        values: Vec<crate::FieldValue>,
    },
    /// Exclude a candidate set with `AND` and the selected adapter's null semantics.
    FieldNotIn {
        /// A registered logical field name or configured storage field name.
        field: String,
        /// Native candidates converted by the selected adapter.
        /// An empty set matches in Memory or SQLite and produces a PostgreSQL or MySQL syntax error.
        values: Vec<crate::FieldValue>,
    },
    /// Apply a typed `AND` condition while retaining the selected code and owner bindings.
    Where(DeviceCodeWhere),
}

/// A DeviceCode ownership condition over a declared field.
/// Fields that reference `id` use the configured ID policy regardless of their declared type.
/// Adapter-specific Date and JSON conversion retains the original operand after Serial conversion.
/// References to other fields retain that field declaration's ordinary query conversions.
#[derive(Debug, Clone, PartialEq)]
pub struct DeviceCodeWhere {
    /// Native `scope`, a registered logical field name, or a configured storage field name.
    pub field: String,
    /// Comparison operator. The default is equality.
    pub operator: WhereOperator,
    /// Native operand, retaining Date and array identity and non-finite numbers.
    /// The selected adapter determines comparison, conversion, and binding errors.
    pub value: crate::FieldValue,
    /// String comparison mode. Range comparisons ignore this setting.
    pub mode: WhereMode,
}

impl DeviceCodeWhere {
    /// Construct a case-sensitive equality condition.
    pub fn new(field: impl Into<String>, value: impl Into<crate::FieldValue>) -> Self {
        Self {
            field: field.into(),
            operator: WhereOperator::Eq,
            value: value.into(),
            mode: WhereMode::Sensitive,
        }
    }
}

/// Operators accepted by the upstream adapter's Where condition.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum WhereOperator {
    /// Equal to the query value.
    #[default]
    Eq,
    /// Not equal to the query value.
    Ne,
    /// Less than the query value.
    Lt,
    /// Less than or equal to the query value.
    Lte,
    /// Greater than the query value.
    Gt,
    /// Greater than or equal to the query value.
    Gte,
    /// Included in the query candidates.
    In,
    /// Excluded from the query candidates.
    NotIn,
    /// Contain the query value with the selected adapter's pattern semantics.
    Contains,
    /// Start with the query value with the selected adapter's pattern semantics.
    StartsWith,
    /// End with the query value with the selected adapter's pattern semantics.
    EndsWith,
}

/// Case handling for string equality, membership, and pattern comparisons.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum WhereMode {
    /// Retain the selected adapter's ordinary comparison behavior.
    #[default]
    Sensitive,
    /// Use the selected adapter's case-insensitive string comparison behavior.
    Insensitive,
}

/// Input for creating a new device authorization code.
#[derive(Debug, Clone)]
pub struct CreateDeviceCode {
    pub device_code: String,
    pub user_code: String,
    pub user_id: Option<String>,
    pub expires_at: crate::FieldDate,
    pub status: String,
    pub last_polled_at: Option<crate::FieldDate>,
    pub polling_interval: Option<f64>,
    pub client_id: Option<String>,
    /// Omit with `Undefined`, clear with `Typed(None)`, or supply a string.
    pub scope: crate::SchemaValue<Option<String>>,
    /// Declared application fields before adapter input policies.
    pub additional_fields: crate::FieldMap,
}

/// Input for updating an existing device authorization code.
#[derive(Debug, Clone, Default)]
pub struct UpdateDeviceCode {
    /// Declared application fields to update; omitted keys retain their stored values.
    pub additional_fields: crate::FieldMap,
    /// Omit with `Undefined`; supplied null and string values pass through field policies.
    pub scope: crate::SchemaValue<Option<String>>,
    /// Update the status. `None` leaves it unchanged.
    pub status: Option<String>,
    /// Update the approving/denying user. `Some(None)` clears it, `None` leaves
    /// it unchanged.
    pub user_id: Option<SchemaValue<Option<String>>>,
    /// Update the last poll timestamp. `Some(None)` clears it, `None` leaves it
    /// unchanged.
    pub last_polled_at: Option<Option<crate::FieldDate>>,
}

/// API key response shape.
#[derive(Debug, Clone)]
pub struct ApiKey {
    /// Source property order, independent of the current typed values.
    pub field_order: Vec<String>,
    /// Declared application fields after adapter output projection.
    pub additional_fields: crate::FieldMap,
    pub id: SchemaValue<String>,
    pub name: SchemaValue<Option<String>>,
    pub start: SchemaValue<Option<crate::ApiKeyStart>>,
    pub prefix: SchemaValue<Option<String>>,
    /// SHA-256 hash of the key (column name: `key` in SQL)
    pub key_hash: SchemaValue<String>,
    pub reference_id: SchemaValue<String>,
    pub config_id: SchemaValue<String>,
    pub refill_interval: SchemaValue<Option<f64>>,
    pub refill_amount: SchemaValue<Option<f64>>,
    pub last_refill_at: SchemaValue<Option<crate::FieldDate>>,
    pub enabled: SchemaValue<bool>,
    pub rate_limit_enabled: SchemaValue<bool>,
    pub rate_limit_time_window: SchemaValue<Option<f64>>,
    pub rate_limit_max: SchemaValue<Option<f64>>,
    pub request_count: SchemaValue<Option<f64>>,
    pub remaining: SchemaValue<Option<f64>>,
    pub last_request: SchemaValue<Option<crate::FieldDate>>,
    pub expires_at: SchemaValue<Option<crate::FieldDate>>,
    pub created_at: SchemaValue<crate::FieldDate>,
    pub updated_at: SchemaValue<crate::FieldDate>,
    pub permissions: SchemaValue<Option<String>>,
    pub metadata: SchemaValue<Option<String>>,
}

impl PartialEq for ApiKey {
    fn eq(&self, other: &Self) -> bool {
        self.additional_fields == other.additional_fields
            && self.id == other.id
            && self.name == other.name
            && self.start == other.start
            && self.prefix == other.prefix
            && self.key_hash == other.key_hash
            && self.reference_id == other.reference_id
            && self.config_id == other.config_id
            && self.refill_interval == other.refill_interval
            && self.refill_amount == other.refill_amount
            && self.last_refill_at == other.last_refill_at
            && self.enabled == other.enabled
            && self.rate_limit_enabled == other.rate_limit_enabled
            && self.rate_limit_time_window == other.rate_limit_time_window
            && self.rate_limit_max == other.rate_limit_max
            && self.request_count == other.request_count
            && self.remaining == other.remaining
            && self.last_request == other.last_request
            && self.expires_at == other.expires_at
            && self.created_at == other.created_at
            && self.updated_at == other.updated_at
            && self.permissions == other.permissions
            && self.metadata == other.metadata
    }
}

/// API key creation data.
#[derive(Debug, Clone)]
pub struct CreateApiKey {
    /// Declared application fields before adapter input policies.
    pub additional_fields: crate::FieldMap,
    /// Owner before adapter policies: a User ID or an Organization ID.
    pub reference_id: SchemaValue<String>,
    /// Name of the API-key configuration this key belongs to.
    pub config_id: String,
    /// Display name before adapter input policies, including JSON values or omission.
    pub name: SchemaValue<Option<String>>,
    pub prefix: Option<String>,
    pub key_hash: String,
    pub start: Option<crate::ApiKeyStart>,
    pub expires_at: Option<crate::FieldDate>,
    pub remaining: Option<f64>,
    pub rate_limit_enabled: bool,
    pub rate_limit_time_window: Option<f64>,
    pub rate_limit_max: Option<f64>,
    pub refill_interval: Option<f64>,
    pub refill_amount: Option<f64>,
    /// Encoded permissions before adapter policies; omission permits declaration defaults.
    pub permissions: SchemaValue<Option<String>>,
    pub metadata: Option<String>,
    /// Enabled value before adapter policies, including replacement types or omission.
    pub enabled: SchemaValue<bool>,
}

/// API key update data.
#[derive(Debug, Clone, Default)]
pub struct UpdateApiKey {
    /// Declared application field patch before adapter input policies.
    pub additional_fields: crate::FieldMap,
    pub name: Option<SchemaValue<Option<String>>>,
    pub enabled: Option<SchemaValue<bool>>,
    pub remaining: Option<f64>,
    pub rate_limit_enabled: Option<bool>,
    pub rate_limit_time_window: Option<f64>,
    pub rate_limit_max: Option<f64>,
    pub refill_interval: Option<f64>,
    pub refill_amount: Option<f64>,
    pub permissions: Option<String>,
    pub metadata: Option<String>,
    /// Update the expiration time. `Some(Some("..."))` sets a new value,
    /// `Some(None)` clears it, `None` leaves it unchanged.
    pub expires_at: Option<Option<crate::FieldDate>>,
    /// Last request timestamp (updated during verify).
    pub last_request: Option<Option<crate::FieldDate>>,
    /// Request count within the current rate-limit window.
    pub request_count: Option<f64>,
    /// Last refill timestamp (updated during verify).
    pub last_refill_at: Option<Option<crate::FieldDate>>,
}

impl AuthTwoFactor for TwoFactor {
    fn field_order(&self) -> Option<&[String]> {
        Some(&self.field_order)
    }
    fn additional_fields(&self) -> Option<&crate::FieldMap> {
        Some(&self.additional_fields)
    }
    fn id(&self) -> SchemaValue<Cow<'_, str>> {
        self.id.as_ref().map(|id| Cow::Borrowed(id.as_str()))
    }
    fn secret(&self) -> &SchemaValue<String> {
        &self.secret
    }
    fn backup_codes(&self) -> &SchemaValue<String> {
        &self.backup_codes
    }
    fn user_id(&self) -> SchemaValue<Cow<'_, str>> {
        self.user_id.as_ref().map(|id| Cow::Borrowed(id.as_str()))
    }
    fn verified(&self) -> &SchemaValue<Option<bool>> {
        &self.verified
    }
    fn failed_verification_count(&self) -> &SchemaValue<Option<f64>> {
        &self.failed_verification_count
    }
    fn locked_until(&self) -> &SchemaValue<Option<crate::FieldDate>> {
        &self.locked_until
    }
    fn created_at(&self) -> &SchemaValue<crate::FieldDate> {
        &self.created_at
    }
    fn updated_at(&self) -> &SchemaValue<crate::FieldDate> {
        &self.updated_at
    }
}

impl<T: AuthTwoFactor> From<&T> for TwoFactor {
    fn from(two_factor: &T) -> Self {
        Self {
            field_order: two_factor.field_order().unwrap_or_default().to_vec(),
            additional_fields: two_factor.additional_fields().cloned().unwrap_or_default(),
            id: two_factor.id().into_owned(),
            secret: two_factor.secret().to_owned(),
            backup_codes: two_factor.backup_codes().to_owned(),
            user_id: two_factor.user_id().into_owned(),
            verified: two_factor.verified().clone(),
            failed_verification_count: two_factor.failed_verification_count().clone(),
            locked_until: two_factor.locked_until().clone(),
            created_at: two_factor.created_at().clone(),
            updated_at: two_factor.updated_at().clone(),
        }
    }
}

impl AuthApiKey for ApiKey {
    fn field_order(&self) -> Option<&[String]> {
        Some(&self.field_order)
    }
    fn additional_fields(&self) -> Option<&crate::FieldMap> {
        Some(&self.additional_fields)
    }
    fn id(&self) -> SchemaValue<Cow<'_, str>> {
        self.id.as_ref().map(|id| Cow::Borrowed(id.as_str()))
    }
    fn name(&self) -> &SchemaValue<Option<String>> {
        &self.name
    }
    fn start(&self) -> &SchemaValue<Option<crate::ApiKeyStart>> {
        &self.start
    }
    fn prefix(&self) -> &SchemaValue<Option<String>> {
        &self.prefix
    }
    fn key_hash(&self) -> &SchemaValue<String> {
        &self.key_hash
    }
    fn reference_id(&self) -> &SchemaValue<String> {
        &self.reference_id
    }
    fn config_id(&self) -> &SchemaValue<String> {
        &self.config_id
    }
    fn refill_interval(&self) -> &SchemaValue<Option<f64>> {
        &self.refill_interval
    }
    fn refill_amount(&self) -> &SchemaValue<Option<f64>> {
        &self.refill_amount
    }
    fn last_refill_at(&self) -> &SchemaValue<Option<crate::FieldDate>> {
        &self.last_refill_at
    }
    fn enabled(&self) -> &SchemaValue<bool> {
        &self.enabled
    }
    fn rate_limit_enabled(&self) -> &SchemaValue<bool> {
        &self.rate_limit_enabled
    }
    fn rate_limit_time_window(&self) -> &SchemaValue<Option<f64>> {
        &self.rate_limit_time_window
    }
    fn rate_limit_max(&self) -> &SchemaValue<Option<f64>> {
        &self.rate_limit_max
    }
    fn request_count(&self) -> &SchemaValue<Option<f64>> {
        &self.request_count
    }
    fn remaining(&self) -> &SchemaValue<Option<f64>> {
        &self.remaining
    }
    fn last_request(&self) -> &SchemaValue<Option<crate::FieldDate>> {
        &self.last_request
    }
    fn expires_at(&self) -> &SchemaValue<Option<crate::FieldDate>> {
        &self.expires_at
    }
    fn created_at(&self) -> &SchemaValue<crate::FieldDate> {
        &self.created_at
    }
    fn updated_at(&self) -> &SchemaValue<crate::FieldDate> {
        &self.updated_at
    }
    fn permissions(&self) -> &SchemaValue<Option<String>> {
        &self.permissions
    }
    fn metadata(&self) -> &SchemaValue<Option<String>> {
        &self.metadata
    }
}

impl<T: AuthApiKey> From<&T> for ApiKey {
    fn from(api_key: &T) -> Self {
        Self {
            field_order: api_key.field_order().unwrap_or_default().to_vec(),
            additional_fields: api_key.additional_fields().cloned().unwrap_or_default(),
            id: api_key.id().into_owned(),
            name: api_key.name().clone(),
            start: api_key.start().clone(),
            prefix: api_key.prefix().clone(),
            key_hash: api_key.key_hash().clone(),
            reference_id: api_key.reference_id().clone(),
            config_id: api_key.config_id().clone(),
            refill_interval: api_key.refill_interval().clone(),
            refill_amount: api_key.refill_amount().clone(),
            last_refill_at: api_key.last_refill_at().clone(),
            enabled: api_key.enabled().clone(),
            rate_limit_enabled: api_key.rate_limit_enabled().clone(),
            rate_limit_time_window: api_key.rate_limit_time_window().clone(),
            rate_limit_max: api_key.rate_limit_max().clone(),
            request_count: api_key.request_count().clone(),
            remaining: api_key.remaining().clone(),
            last_request: api_key.last_request().clone(),
            expires_at: api_key.expires_at().clone(),
            created_at: api_key.created_at().clone(),
            updated_at: api_key.updated_at().clone(),
            permissions: api_key.permissions().clone(),
            metadata: api_key.metadata().clone(),
        }
    }
}

impl AuthPasskey for Passkey {
    fn field_order(&self) -> Option<&[String]> {
        Some(&self.field_order)
    }
    fn additional_fields(&self) -> Option<&crate::FieldMap> {
        Some(&self.additional_fields)
    }
    fn id(&self) -> SchemaValue<Cow<'_, str>> {
        self.id.as_ref().map(|id| Cow::Borrowed(id.as_str()))
    }
    fn name(&self) -> &SchemaValue<Option<String>> {
        &self.name
    }
    fn public_key(&self) -> &SchemaValue<String> {
        &self.public_key
    }
    fn user_id(&self) -> SchemaValue<Cow<'_, str>> {
        self.user_id.as_ref().map(|id| Cow::Borrowed(id.as_str()))
    }
    fn credential_id(&self) -> &SchemaValue<String> {
        &self.credential_id
    }
    fn counter(&self) -> &SchemaValue<u64> {
        &self.counter
    }
    fn device_type(&self) -> &SchemaValue<String> {
        &self.device_type
    }
    fn backed_up(&self) -> &SchemaValue<bool> {
        &self.backed_up
    }
    fn transports(&self) -> &SchemaValue<Option<String>> {
        &self.transports
    }
    fn created_at(&self) -> &SchemaValue<Option<crate::FieldDate>> {
        &self.created_at
    }
    fn updated_at(&self) -> &SchemaValue<crate::FieldDate> {
        &self.updated_at
    }
    fn aaguid(&self) -> &SchemaValue<Option<String>> {
        &self.aaguid
    }
    fn credential(&self) -> &SchemaValue<String> {
        &self.credential
    }
}

impl<T: AuthPasskey> From<&T> for Passkey {
    fn from(passkey: &T) -> Self {
        Self {
            field_order: passkey.field_order().unwrap_or_default().to_vec(),
            additional_fields: passkey.additional_fields().cloned().unwrap_or_default(),
            id: passkey.id().into_owned(),
            name: passkey.name().clone(),
            public_key: passkey.public_key().clone(),
            user_id: passkey.user_id().into_owned(),
            credential_id: passkey.credential_id().clone(),
            counter: passkey.counter().clone(),
            device_type: passkey.device_type().clone(),
            backed_up: passkey.backed_up().clone(),
            transports: passkey.transports().clone(),
            created_at: passkey.created_at().clone(),
            updated_at: passkey.updated_at().clone(),
            aaguid: passkey.aaguid().clone(),
            credential: passkey.credential().clone(),
        }
    }
}

/// Persisted SIWE wallet identity. Multiple chains can belong to one user.
#[derive(Debug, Clone, Default)]
pub struct WalletAddress {
    /// Source property order, independent of the current typed values.
    pub field_order: Vec<String>,
    pub id: SchemaValue<String>,
    pub user_id: SchemaValue<String>,
    pub address: SchemaValue<String>,
    pub chain_id: SchemaValue<f64>,
    pub is_primary: SchemaValue<bool>,
    pub created_at: SchemaValue<crate::FieldDate>,
    /// Declared application fields returned by the adapter.
    pub additional_fields: crate::FieldMap,
}

impl PartialEq for WalletAddress {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id
            && self.user_id == other.user_id
            && self.address == other.address
            && self.chain_id == other.chain_id
            && self.is_primary == other.is_primary
            && self.created_at == other.created_at
            && self.additional_fields == other.additional_fields
    }
}

/// SIWE wallet creation data. The adapter generates the model ID.
#[derive(Debug, Clone)]
pub struct CreateWalletAddress {
    pub user_id: String,
    pub address: String,
    pub chain_id: i64,
    pub is_primary: bool,
    pub created_at: crate::FieldDate,
    /// Logical application fields consumed by registered adapter policies.
    pub additional_fields: crate::FieldMap,
}
