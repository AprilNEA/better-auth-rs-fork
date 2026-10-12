use super::{AuthResult, AuthSchema, FieldValue, SecondaryStore, active_sessions_key, references};
use crate::utils::json::safe_parse_field;

impl<S: AuthSchema> SecondaryStore<S> {
    pub(super) async fn delete_runtime_session(&self, token: &FieldValue) -> AuthResult<()> {
        let Some(storage) = &self.storage else {
            return self.inner.delete_session_by_token_value(token).await;
        };
        if let Some(cached) = storage
            .get_native(token)
            .await?
            .filter(FieldValue::is_truthy)
        {
            let cached = safe_parse_field(&cached)?;
            let session = if cached.is_null() || cached.is_undefined() {
                FieldValue::Undefined
            } else {
                cached.model_property("session")?
            };
            if !session.is_truthy() {
                self.config
                    .logger()?
                    .error("Session not found in secondary storage", &[])?;
                return Ok(());
            }
            let user_id = session.model_property("userId")?;
            let key = active_sessions_key(&user_id)?;
            if let Some(current) = storage
                .get_native(&key)
                .await?
                .filter(FieldValue::is_truthy)
            {
                let current = safe_parse_field(&current)?;
                let list = if current.is_truthy() {
                    current
                } else {
                    references::empty()
                };
                let now = self.now();
                let filter_token = token.clone();
                let filtered = references::filter(&list, move |session| {
                    let expires_at =
                        crate::query::field_number(&session.model_property("expiresAt")?)?;
                    Ok(expires_at > now.timestamp_millis() as f64
                        && !session
                            .model_property("token")?
                            .strict_equals(&filter_token))
                })?;
                let sorted = references::sort(&filtered)?;
                let furthest = references::last_expiration(&sorted)?;
                if crate::query::field_number(&filtered.model_property("length")?)? > 0.0
                    && furthest.is_truthy()
                    && crate::query::field_number(&furthest)? > self.now().timestamp_millis() as f64
                {
                    self.write_references(
                        &active_sessions_key(&user_id)?,
                        &filtered,
                        furthest,
                        now,
                    )
                    .await?;
                } else {
                    storage
                        .delete_native(&active_sessions_key(&user_id)?)
                        .await?;
                }
            } else {
                self.config
                    .logger()?
                    .error("Active sessions list not found in secondary storage", &[])?;
            }
        }
        storage.delete_native(token).await?;
        if !self.database_sessions() {
            return Ok(());
        }
        if self.config.session.preserve_session_in_database() {
            self.inner.end_session_by_token_value(token).await
        } else {
            self.inner.delete_session_by_token_value(token).await
        }
    }
}

#[cfg(test)]
mod tests;
