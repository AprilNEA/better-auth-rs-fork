use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use better_auth_core::{
    AuthContext, AuthError, AuthResult, AuthSchema, CreateVerification, FieldDate, FieldValue,
    SchemaValue,
};
use hmac::{Hmac, Mac};
use rand::Rng;
use sha2::{Digest, Sha256};

use super::EmailOtpCallbacks;
use super::{EmailOtpMessage, EmailOtpPlugin, EmailOtpStorage, EmailOtpType};
use crate::plugins::endpoint_context::EndpointContext;
use crate::plugins::symmetric::{decrypt_field, encrypt};
use std::sync::Arc;

#[cfg(test)]
#[path = "native_value_tests.rs"]
mod native_value_tests;

pub(super) fn invalid_otp() -> AuthError {
    AuthError::from_code("BAD_REQUEST", "INVALID_OTP", "Invalid OTP")
}
fn expired_otp() -> AuthError {
    AuthError::from_code("BAD_REQUEST", "OTP_EXPIRED", "OTP expired")
}
fn too_many_attempts() -> AuthError {
    AuthError::from_code("FORBIDDEN", "TOO_MANY_ATTEMPTS", "Too many attempts")
}

impl EmailOtpPlugin {
    fn attempts(&self) -> u32 {
        if self.config.allowed_attempts == 0 {
            3
        } else {
            self.config.allowed_attempts
        }
    }
    pub(super) fn has_sender<S: AuthSchema>(&self, ctx: &AuthContext<S>) -> bool {
        self.config.sender.is_some()
            || ctx
                .extensions
                .get::<Arc<EmailOtpCallbacks<S>>>()
                .is_some_and(|callbacks| callbacks.sender.is_some())
    }
    fn generate<S: AuthSchema>(
        &self,
        endpoint: &EndpointContext<'_, S>,
        email: &str,
        kind: EmailOtpType,
    ) -> AuthResult<String> {
        let code = if let Some(generator) = endpoint
            .auth
            .extensions
            .get::<Arc<EmailOtpCallbacks<S>>>()
            .and_then(|callbacks| callbacks.generator.as_ref())
        {
            generator(email, kind, endpoint)?
        } else {
            self.config
                .generate_otp
                .as_ref()
                .and_then(|generate| generate(email, kind))
        };
        Ok(code.filter(|otp| !otp.is_empty()).unwrap_or_else(|| {
            (0..self.config.otp_length)
                .map(|_| char::from(b'0' + rand::thread_rng().gen_range(0..10)))
                .collect()
        }))
    }
    async fn store_code(
        &self,
        code: &str,
        secret: better_auth_core::SecretKey<'_>,
    ) -> AuthResult<String> {
        match &self.config.storage {
            EmailOtpStorage::Plain => Ok(code.to_owned()),
            EmailOtpStorage::Hashed => Ok(URL_SAFE_NO_PAD.encode(Sha256::digest(code.as_bytes()))),
            EmailOtpStorage::Encrypted => encrypt(secret, code),
            EmailOtpStorage::CustomHash(hash) => hash(code.to_owned()).await,
            EmailOtpStorage::CustomEncryption(codec) => codec.encode(code).await,
        }
    }
    pub(super) async fn recover(
        &self,
        code: &FieldValue,
        secret: better_auth_core::SecretKey<'_>,
    ) -> AuthResult<FieldValue> {
        match &self.config.storage {
            EmailOtpStorage::Plain => Ok(code.clone()),
            EmailOtpStorage::Hashed | EmailOtpStorage::CustomHash(_) => Ok(FieldValue::Null),
            EmailOtpStorage::Encrypted => decrypt_field(secret, code).map(Into::into),
            EmailOtpStorage::CustomEncryption(codec) => {
                let code = SchemaValue::<String>::from_field(code.clone());
                codec.decode(code.typed()?).await.map(Into::into)
            }
        }
    }
    async fn matches(
        &self,
        stored: &FieldValue,
        provided: &str,
        secret: better_auth_core::SecretKey<'_>,
    ) -> AuthResult<bool> {
        let (left, right) = match &self.config.storage {
            EmailOtpStorage::Encrypted | EmailOtpStorage::CustomEncryption(_) => {
                (self.recover(stored, secret).await?, provided.into())
            }
            EmailOtpStorage::Hashed | EmailOtpStorage::CustomHash(_) => (
                self.store_code(provided, secret).await?.into(),
                stored.clone(),
            ),
            EmailOtpStorage::Plain => (provided.into(), stored.clone()),
        };
        let left = comparison_bytes(&left)?;
        let right = comparison_bytes(&right)?;
        // HMAC verification compares fixed-size tags without exposing a matching code prefix.
        let secret = secret.current()?;
        let mut expected = Hmac::<Sha256>::new_from_slice(secret.as_bytes())
            .map_err(|error| AuthError::internal(error.to_string()))?;
        expected.update(&left);
        let mut actual = Hmac::<Sha256>::new_from_slice(secret.as_bytes())
            .map_err(|error| AuthError::internal(error.to_string()))?;
        actual.update(&right);
        Ok(actual
            .verify_slice(&expected.finalize().into_bytes())
            .is_ok())
    }
    pub(super) async fn deliver<S: AuthSchema>(
        &self,
        endpoint: &EndpointContext<'_, S>,
        email: &str,
        otp: impl Into<FieldValue> + Send,
        kind: EmailOtpType,
    ) -> AuthResult<()> {
        let message = EmailOtpMessage {
            email: email.to_owned(),
            otp: SchemaValue::from_field(otp.into()),
            kind,
        };
        let task: Option<better_auth_core::background::BackgroundFuture> = if let Some(sender) =
            endpoint
                .auth
                .extensions
                .get::<Arc<EmailOtpCallbacks<S>>>()
                .and_then(|callbacks| callbacks.sender.as_ref())
        {
            sender(&message, endpoint)?
        } else {
            let sender = self
                .config
                .sender
                .as_ref()
                .ok_or_else(|| {
                    AuthError::from_status(
                        "BAD_REQUEST",
                        better_auth_core::FieldMap::from([(
                            "message".into(),
                            "send email verification is not implemented".into(),
                        )])
                        .into(),
                    )
                })?
                .clone();
            Some(Box::pin(async move { sender.send(&message).await }))
        };
        better_auth_core::background::run_or_await(
            task,
            endpoint.auth.config.advanced.background_tasks.as_ref(),
            endpoint.auth.logger(),
        )
        .await;
        Ok(())
    }
    pub(super) async fn create_otp(
        &self,
        endpoint: &EndpointContext<'_, impl AuthSchema>,
        email: &str,
        kind: EmailOtpType,
        identifier: &str,
    ) -> AuthResult<String> {
        let ctx = endpoint.auth;
        let otp = self.generate(endpoint, email, kind)?;
        let stored = self
            .store_code(&otp, ctx.config.encryption_secret())
            .await?;
        let input = CreateVerification {
            identifier: (identifier.to_owned()).into(),
            value: (format!("{stored}:0")).into(),
            expires_at: (ctx.now() + self.config.expires_in).into(),
            ..Default::default()
        };
        let _ = match endpoint.transaction {
            Some(transaction) => transaction.create_verification_optional(input).await?,
            None => ctx.database.create_verification_optional(input).await?,
        };
        Ok(otp)
    }
    pub(super) async fn resolve_otp(
        &self,
        endpoint: &EndpointContext<'_, impl AuthSchema>,
        email: &str,
        kind: EmailOtpType,
    ) -> AuthResult<FieldValue> {
        let identifier = kind.identifier(email);
        if self.config.reuse_otp {
            let otp = self.try_reuse_otp(endpoint, &identifier).await?;
            if otp.is_truthy() {
                return Ok(otp);
            }
        }
        self.create_otp(endpoint, email, kind, &identifier)
            .await
            .map(Into::into)
    }

    pub(super) async fn try_reuse_otp(
        &self,
        endpoint: &EndpointContext<'_, impl AuthSchema>,
        identifier: &str,
    ) -> AuthResult<FieldValue> {
        let ctx = endpoint.auth;
        let existing = match endpoint.transaction {
            Some(transaction) => transaction.find_verification_value(identifier).await?,
            None => ctx.database.find_verification_value(identifier).await?,
        };
        let Some(existing) = existing.filter(FieldValue::is_truthy) else {
            return Ok(FieldValue::Null);
        };
        if SchemaValue::<FieldDate>::from_field(existing.model_property("expiresAt")?)
            .is_before(ctx.now())?
        {
            return Ok(FieldValue::Null);
        }
        let (stored, attempts) = split(&existing.model_property("value")?)?;
        if attempts.is_truthy() && parse_attempts(&attempts)? >= f64::from(self.attempts()) {
            return Ok(FieldValue::Null);
        }
        let otp = self
            .recover(&stored, ctx.config.encryption_secret())
            .await?;
        if !otp.is_truthy() {
            return Ok(FieldValue::Null);
        }
        let update = better_auth_core::store::database_hooks::VerificationUpdate {
            expires_at: (ctx.now() + self.config.expires_in).into(),
            ..Default::default()
        };
        let _ = match endpoint.transaction {
            Some(transaction) => {
                transaction
                    .update_verification_value(identifier, update)
                    .await?
            }
            None => {
                ctx.database
                    .update_verification_value(identifier, update)
                    .await?
            }
        };
        Ok(otp)
    }

    pub(super) async fn verify_otp(
        &self,
        ctx: &AuthContext<impl AuthSchema>,
        identifier: &str,
        provided: &str,
        consume: bool,
    ) -> AuthResult<()> {
        let existing = ctx
            .database
            .find_verification_value(identifier)
            .await?
            .filter(FieldValue::is_truthy);
        if let Some(row) = &existing
            && SchemaValue::<FieldDate>::from_field(row.model_property("expiresAt")?)
                .is_before(ctx.now())?
        {
            ctx.database
                .delete_verification_by_identifier(identifier)
                .await?;
            return Err(expired_otp());
        }
        let record = if consume {
            ctx.database
                .consume_verification_by_identifier(identifier)
                .await?
                .map(|record| record.fields().map(FieldValue::from))
                .transpose()?
        } else {
            existing
        }
        .ok_or_else(invalid_otp)?;
        let (stored, attempts) = split(&record.model_property("value")?)?;
        let used_attempts = if consume {
            Some(parse_attempts(if attempts.is_truthy() {
                &attempts
            } else {
                &"0".into()
            })?)
        } else {
            None
        };
        let exhausted = match used_attempts {
            Some(attempts) => attempts >= f64::from(self.attempts()),
            None => {
                attempts.is_truthy() && parse_attempts(&attempts)? >= f64::from(self.attempts())
            }
        };
        if exhausted {
            if !consume {
                ctx.database
                    .delete_verification_by_identifier(identifier)
                    .await?;
            }
            return Err(too_many_attempts());
        }
        if !self
            .matches(&stored, provided, ctx.config.encryption_secret())
            .await?
        {
            let mut value = stored.display_utf16()?.as_utf16().to_vec();
            let attempts = match used_attempts {
                Some(attempts) => attempts,
                None => parse_attempts(if attempts.is_truthy() {
                    &attempts
                } else {
                    &"0".into()
                })?,
            };
            value.extend(
                format!(
                    ":{}",
                    better_auth_core::schema_value::number_string(attempts + 1.0)
                )
                .encode_utf16(),
            );
            let value = better_auth_core::Utf16String::from_units(value).into();
            if consume {
                let _ = ctx
                    .database
                    .create_verification_optional(CreateVerification {
                        field_order: ["value", "identifier", "expiresAt"]
                            .map(str::to_owned)
                            .into(),
                        identifier: (identifier.to_owned()).into(),
                        value: SchemaValue::from_field(value),
                        expires_at: SchemaValue::from_field(record.model_property("expiresAt")?),
                        ..Default::default()
                    })
                    .await?;
            } else {
                let _ = ctx
                    .database
                    .update_verification_value(
                        identifier,
                        better_auth_core::store::database_hooks::VerificationUpdate {
                            value: SchemaValue::from_field(value),
                            ..Default::default()
                        },
                    )
                    .await?;
            }
            return Err(invalid_otp());
        }
        Ok(())
    }
}

pub(super) fn split(value: &FieldValue) -> AuthResult<(FieldValue, FieldValue)> {
    let index = value.last_index_of_method(&":".into(), "input")?;
    if index.strict_equals(&(-1).into()) {
        return Ok((value.clone(), "".into()));
    }
    let stored = value.slice_method(&0.into(), Some(&index), "input")?;
    let attempts = value.slice_method(
        &better_auth_core::query::field_add(&index, &1.into())?,
        None,
        "input",
    )?;
    Ok((stored, attempts))
}

fn parse_attempts(value: &FieldValue) -> AuthResult<f64> {
    Ok(better_auth_core::query::parse_integer(
        &String::from_utf16_lossy(value.display_utf16()?.as_utf16()),
    ))
}

/// Match crypto/buffer's TextEncoder and Uint8Array input boundary.
fn comparison_bytes(value: &FieldValue) -> AuthResult<Vec<u8>> {
    fn byte(value: &FieldValue) -> AuthResult<u8> {
        let value = better_auth_core::query::field_number(value)?;
        Ok(if value.is_finite() {
            value.trunc().rem_euclid(256.0) as u8
        } else {
            0
        })
    }

    match value {
        FieldValue::String(text) => Ok(text.as_bytes().to_vec()),
        FieldValue::Utf16String(text) => Ok(String::from_utf16_lossy(text.as_utf16()).into_bytes()),
        FieldValue::Array(array) => {
            // TypedArray consumes the intrinsic iterator before converting its collected elements.
            let mut values = Vec::new();
            while values.len() < array.len()? {
                values.push(array.get(values.len())?.unwrap_or(FieldValue::Undefined));
            }
            values.iter().map(byte).collect()
        }
        value => {
            let object = matches!(
                value,
                FieldValue::Object(_) | FieldValue::Date(_) | FieldValue::Function(_)
            );
            let length = if object {
                better_auth_core::query::field_number(&value.model_property("length")?)?
            } else {
                better_auth_core::query::field_number(value)?
            };
            let length = if length.is_nan() { 0.0 } else { length.trunc() };
            let length = if object {
                length.clamp(0.0, 9_007_199_254_740_991.0)
            } else if !(0.0..=9_007_199_254_740_991.0).contains(&length) {
                return Err(AuthError::RangeError("length is out of range".into()));
            } else {
                length
            } as usize;
            let mut bytes = Vec::new();
            bytes.try_reserve_exact(length).map_err(|error| {
                AuthError::internal(format!("Allocate native OTP comparison bytes: {error}"))
            })?;
            if object {
                for index in 0..length {
                    bytes.push(byte(&value.model_property(&index.to_string())?)?);
                }
            } else {
                bytes.resize(length, 0);
            }
            Ok(bytes)
        }
    }
}
