use super::*;

#[cfg(test)]
mod duration_tests;

impl AccountLockout {
    fn locked_until(&self, now: chrono::DateTime<Utc>) -> better_auth_core::FieldDate {
        better_auth_core::FieldDate::from_milliseconds(
            now.timestamp_millis() as f64 + self.duration_seconds * 1000.0,
        )
    }
}

pub(super) async fn assert_not_locked(
    state: &ResolvedTwoFactorState,
    factor: &TwoFactor,
    config: &AccountLockout,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
) -> AuthResult<()> {
    if !state.is_sign_in() || !config.enabled {
        return Ok(());
    }
    let until = factor.locked_until.field_value();
    if until.is_truthy() {
        if better_auth_core::query::field_date(&until)?.milliseconds()
            > Utc::now().timestamp_millis() as f64
        {
            return Err(AuthError::from_code(
                "TOO_MANY_REQUESTS",
                "ACCOUNT_TEMPORARILY_LOCKED",
                "Too many failed verification attempts. Your account is temporarily locked. Please try again later.",
            ));
        }
        ctx.database
            .reset_two_factor_failures(&factor.id, Some(Utc::now().into()))
            .await?;
    }
    Ok(())
}

pub(super) async fn record_failure(
    state: &ResolvedTwoFactorState,
    factor: &TwoFactor,
    config: &AccountLockout,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
) -> AuthResult<()> {
    if state.is_sign_in() && config.enabled {
        ctx.database
            .record_two_factor_failure(&factor.id, config.max_failed_attempts, &|| {
                Ok(config.locked_until(Utc::now()))
            })
            .await?;
    }
    Ok(())
}

pub(super) async fn reset_failures(
    state: &ResolvedTwoFactorState,
    factor: &TwoFactor,
    config: &AccountLockout,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
) -> AuthResult<()> {
    if state.is_sign_in() && config.enabled {
        ctx.database
            .reset_two_factor_failures(&factor.id, None)
            .await?;
    }
    Ok(())
}

pub(super) struct ChallengeAttempt {
    identifier: String,
    failures: usize,
    verification: better_auth_core::FieldValue,
}

pub(super) async fn begin_attempt<S: better_auth_core::AuthSchema>(
    state: &ResolvedTwoFactorState,
    req: &AuthRequest,
    ctx: &AuthContext<S>,
    limit: usize,
) -> AuthResult<Option<ChallengeAttempt>> {
    let ResolvedTwoFactorState::Pending(pending) = state else {
        return Ok(None);
    };
    let identifier = format!("2fa-attempts-{}", pending.key);
    let consumed = ctx
        .database
        .consume_verification_by_identifier(&identifier)
        .await
        .ok()
        .flatten()
        .ok_or_else(|| {
            AuthError::from_code(
                "UNAUTHORIZED",
                "INVALID_TWO_FACTOR_COOKIE",
                "Invalid two factor cookie",
            )
        })?;
    let parsed = better_auth_core::query::field_number(&consumed.value.field_value())?;
    let attempts = if parsed.is_finite() && parsed.fract() == 0.0 && parsed >= 0.0 {
        parsed
    } else {
        limit as f64
    };
    if attempts >= limit as f64 {
        let invalidation = ctx
            .database
            .consume_verification_by_identifier(&pending.key)
            .await;
        req.append_response_header(
            "Set-Cookie",
            clear_cookie_header(req, &ctx.config, TWO_FACTOR_COOKIE_SUFFIX)?,
        )?;
        if invalidation.is_err() {
            return Err(AuthError::from_code(
                "INTERNAL_SERVER_ERROR",
                "FAILED_TO_INVALIDATE_TWO_FACTOR_CHALLENGE",
                "Failed to invalidate two-factor challenge",
            ));
        }
        return Err(AuthError::from_code(
            "BAD_REQUEST",
            "TOO_MANY_ATTEMPTS_REQUEST_NEW_CODE",
            "Too many attempts. Please request a new code.",
        ));
    }
    Ok(Some(ChallengeAttempt {
        identifier,
        failures: attempts as usize,
        verification: pending.verification.clone(),
    }))
}

pub(super) async fn finish_attempt(
    attempt: Option<ChallengeAttempt>,
    failed: bool,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
) -> AuthResult<FieldValue> {
    if let Some(attempt) = attempt {
        let verification = CreateVerification {
            field_order: ["value", "identifier", "expiresAt"]
                .map(str::to_owned)
                .into(),
            identifier: (attempt.identifier).into(),
            value: ((attempt.failures + usize::from(failed)).to_string()).into(),
            expires_at: better_auth_core::SchemaValue::from_field(
                attempt.verification.model_property("expiresAt")?,
            ),
            ..Default::default()
        };
        // The upstream Promise catch ignores storage errors after reading the challenge expiry.
        return match ctx
            .database
            .create_verification_optional(verification)
            .await
        {
            Ok(Some(record)) => record.fields().map(Into::into),
            Ok(None) => Ok(FieldValue::Null),
            Err(_) => Ok(FieldValue::Undefined),
        };
    }
    Ok(FieldValue::Undefined)
}
