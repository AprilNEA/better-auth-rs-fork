use std::{future::Future, pin::Pin, sync::Arc};

use async_trait::async_trait;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use better_auth_core::{AuthError, AuthResult, FieldArray, FieldValue, SecretKey};
use rand::{Rng, distributions::Alphanumeric};
use sha2::{Digest, Sha256};

/// Application hashing callback for stored second-factor codes.
pub type TwoFactorHasher =
    Arc<dyn Fn(String) -> Pin<Box<dyn Future<Output = AuthResult<String>> + Send>> + Send + Sync>;

/// Reversible application encryption for OTPs or serialized backup codes.
#[async_trait]
pub trait TwoFactorCipher: Send + Sync {
    /// Encrypt plaintext before persistence.
    async fn encrypt(&self, plaintext: &str) -> AuthResult<String>;
    /// Decrypt a stored value before verification.
    async fn decrypt(&self, ciphertext: &str) -> AuthResult<String>;
    /// Receive the native plaintext and retain the callback's stored representation.
    ///
    /// Backup-code JSON serialization can produce `FieldValue::Undefined`. Override
    /// this method to consume that value; the default adapts string inputs to `encrypt`.
    async fn encrypt_native(&self, plaintext: &FieldValue) -> AuthResult<FieldValue> {
        self.encrypt(&cipher_string(plaintext, "plaintext")?)
            .await
            .map(Into::into)
    }
    /// Receive the projected ciphertext before JSON parsing or text encoding.
    async fn decrypt_native(&self, ciphertext: &FieldValue) -> AuthResult<FieldValue> {
        self.decrypt(&cipher_string(ciphertext, "ciphertext")?)
            .await
            .map(Into::into)
    }
}

/// Storage protection for delivered second-factor OTPs.
#[derive(Clone, Default)]
pub enum TwoFactorOtpStorage {
    /// Store the original code, matching the upstream default.
    #[default]
    Plain,
    /// Store an unpadded base64url SHA-256 digest.
    Hashed,
    /// Encrypt using the authentication secret.
    Encrypted,
    /// Hash using an asynchronous application callback.
    CustomHash(TwoFactorHasher),
    /// Encrypt and decrypt using application callbacks.
    CustomEncryption(Arc<dyn TwoFactorCipher>),
}

impl TwoFactorOtpStorage {
    pub(super) async fn encode(
        &self,
        value: &str,
        secret: SecretKey<'_>,
    ) -> AuthResult<FieldValue> {
        let encoded = match self {
            Self::Plain => Ok(value.to_owned()),
            Self::Hashed => Ok(URL_SAFE_NO_PAD.encode(Sha256::digest(value.as_bytes()))),
            Self::Encrypted => crate::plugins::symmetric::encrypt(secret, value),
            Self::CustomHash(hash) => hash(value.to_owned()).await,
            Self::CustomEncryption(cipher) => {
                return cipher.encrypt_native(&FieldValue::from(value)).await;
            }
        }?;
        Ok(encoded.into())
    }

    pub(super) async fn verify(
        &self,
        stored: &FieldValue,
        input: &str,
        secret: SecretKey<'_>,
    ) -> AuthResult<bool> {
        let (stored, input) = match self {
            Self::Encrypted => (
                crate::plugins::symmetric::decrypt_field(secret, stored)?.into(),
                input.into(),
            ),
            Self::CustomEncryption(cipher) => (cipher.decrypt_native(stored).await?, input.into()),
            _ => (stored.clone(), self.encode(input, secret).await?),
        };
        let stored = text_encoder_bytes(&stored)?;
        let input = text_encoder_bytes(&input)?;
        Ok(stored.len() == input.len() && openssl::memcmp::eq(&stored, &input))
    }
}

/// Storage protection for serialized backup codes.
#[derive(Clone, Default)]
pub enum BackupCodeStorage {
    /// Store the JSON serialization result unchanged, including undefined.
    Plain,
    /// Encrypt using the authentication secret, matching the upstream default.
    #[default]
    Encrypted,
    /// Encrypt and decrypt serialized backup values using application callbacks.
    Custom(Arc<dyn TwoFactorCipher>),
}

impl BackupCodeStorage {
    pub(super) async fn encode(
        &self,
        codes: &FieldValue,
        secret: SecretKey<'_>,
    ) -> AuthResult<FieldValue> {
        let json = codes.stringify_native()?;
        match self {
            Self::Plain => Ok(json),
            Self::Encrypted => {
                crate::plugins::symmetric::encrypt_field(secret, &json).map(Into::into)
            }
            Self::Custom(cipher) => cipher.encrypt_native(&json).await,
        }
    }

    pub(super) async fn decode(
        &self,
        stored: &FieldValue,
        secret: SecretKey<'_>,
    ) -> AuthResult<FieldValue> {
        let value = match self {
            Self::Plain => stored.clone(),
            Self::Encrypted => crate::plugins::symmetric::decrypt_field(secret, stored)?.into(),
            Self::Custom(cipher) => cipher.decrypt_native(stored).await?,
        };
        better_auth_core::utils::json::safe_parse_field(&value)
    }
}

fn cipher_string(value: &FieldValue, parameter: &str) -> AuthResult<String> {
    match value {
        FieldValue::String(value) => Ok(value.clone()),
        FieldValue::Utf16String(value) => value
            .to_utf8()
            .map_err(|error| AuthError::internal(error.to_string())),
        _ => Err(AuthError::internal(format!(
            "The string cipher callback requires string {parameter}"
        ))),
    }
}

fn text_encoder_bytes(value: &FieldValue) -> AuthResult<Vec<u8>> {
    if value.is_undefined() {
        return Ok(Vec::new());
    }
    Ok(String::from_utf16_lossy(value.display_utf16()?.as_utf16()).into_bytes())
}

pub(super) struct BackupCodeVerification {
    pub(super) status: FieldValue,
    pub(super) updated: FieldValue,
}

/// Evaluate both methods before the route decides whether verification succeeded.
pub(super) fn verify_backup_code(
    codes: &FieldValue,
    code: &str,
) -> AuthResult<BackupCodeVerification> {
    if !codes.is_truthy() {
        return Ok(BackupCodeVerification {
            status: false.into(),
            updated: FieldValue::Null,
        });
    }
    let code = FieldValue::from(code);
    let status = codes.includes_method(&code, "codes")?;
    let predicate = better_auth_core::FieldFunction::contextual(move |_, arguments| {
        Ok((!arguments
            .first()
            .unwrap_or(&FieldValue::Undefined)
            .strict_equals(&code))
        .into())
    });
    let updated = codes.filter_method(&predicate, "codes")?;
    Ok(BackupCodeVerification { status, updated })
}

/// Recovery-code generation and passwordless management policy.
#[derive(Clone)]
pub struct BackupCodeOptions {
    /// Number of generated codes. Zero produces an empty list.
    pub amount: usize,
    /// Number of random characters, before the separator after character five.
    pub length: usize,
    /// Replace random generation with application-supplied codes.
    pub generate: Option<Arc<dyn Fn() -> Vec<String> + Send + Sync>>,
    /// Generate native backup codes. This callback takes precedence over `generate`.
    /// Errors propagate before encoding or persistence.
    pub generate_native: Option<Arc<dyn Fn() -> AuthResult<FieldValue> + Send + Sync>>,
    /// Stored backup-code representation.
    pub storage: BackupCodeStorage,
    /// Override the plugin's passwordless policy for regeneration.
    pub allow_passwordless: Option<bool>,
}

impl Default for BackupCodeOptions {
    fn default() -> Self {
        Self {
            amount: 10,
            length: 10,
            generate: None,
            generate_native: None,
            storage: BackupCodeStorage::Encrypted,
            allow_passwordless: None,
        }
    }
}

pub(super) struct GeneratedBackupCodes {
    pub(super) backup_codes: FieldValue,
    pub(super) encrypted_backup_codes: FieldValue,
}

impl BackupCodeOptions {
    pub(super) async fn generate(&self, secret: SecretKey<'_>) -> AuthResult<GeneratedBackupCodes> {
        let backup_codes = self.generate_codes()?;
        let encrypted_backup_codes = self.storage.encode(&backup_codes, secret).await?;
        Ok(GeneratedBackupCodes {
            backup_codes,
            encrypted_backup_codes,
        })
    }

    fn generate_codes(&self) -> AuthResult<FieldValue> {
        if let Some(generate) = &self.generate_native {
            return generate();
        }
        if let Some(generate) = &self.generate {
            return Ok(generate()
                .into_iter()
                .map(FieldValue::from)
                .collect::<FieldArray>()
                .into());
        }
        Ok((0..self.amount)
            .map(|_| {
                let code: String = rand::thread_rng()
                    .sample_iter(&Alphanumeric)
                    .take(self.length)
                    .map(char::from)
                    .collect();
                let (prefix, suffix) = code.split_at(code.len().min(5));
                FieldValue::from(format!("{prefix}-{suffix}"))
            })
            .collect::<FieldArray>()
            .into())
    }
}
