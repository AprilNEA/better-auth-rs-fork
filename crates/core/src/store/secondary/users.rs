use super::{
    SecondaryStore, cache,
    sessions::{active_sessions_key, references},
};
use crate::store::{AuthTransaction, UserStore};
use crate::types::{CreateUser, ListUsersParams, UpdateUser};
use crate::wire::UserView;
use crate::{AuthError, AuthResult, AuthSchema, FieldDate, FieldMap, FieldValue, SchemaValue};
use async_trait::async_trait;

#[cfg(test)]
mod native_contract;
#[cfg(test)]
mod tests;

impl<S: AuthSchema> SecondaryStore<S> {
    pub(super) async fn queue_user_session_refresh(
        &self,
        user: Option<UserView>,
        transaction: Option<&dyn AuthTransaction<S>>,
    ) -> AuthResult<()> {
        let runtime = self.clone();
        let effect = Box::pin(async move {
            // Only refresh failures use the upstream onError policy; ordinary after hooks propagate.
            if let Err(error) = runtime.refresh_user_sessions(user.as_ref()).await {
                runtime.config.logger()?.error(
                    "Failed to refresh committed user sessions in secondary storage",
                    &[crate::observability::LogArgument::Error(&error)],
                )?;
            }
            Ok(())
        });
        match transaction {
            Some(transaction) => transaction.queue_after_commit(effect),
            None => effect.await,
        }
    }

    async fn refresh_user_sessions(&self, user: Option<&UserView>) -> AuthResult<()> {
        if self.storage.is_none() {
            return Ok(());
        }
        let user =
            user.ok_or_else(|| AuthError::internal("Cannot refresh sessions for a missing user"))?;
        let raw = self
            .secondary()?
            .get_native(&active_sessions_key(&user.id.field_value())?)
            .await?;
        if !raw.as_ref().is_some_and(FieldValue::is_truthy) {
            return Ok(());
        }
        let now = self.now();
        let references = cache::decode(raw)?.unwrap_or_else(references::empty);
        let references = references::filter(&references, move |reference| {
            Ok(
                crate::query::field_number(&reference.model_property("expiresAt")?)?
                    > now.timestamp_millis() as f64,
            )
        })?;
        let unsupported_map = |method| match method {
            FieldValue::Function(_) => {
                AuthError::config("Native async session-refresh map callbacks are not supported")
            }
            _ => AuthError::type_error("validSessions.map is not a function"),
        };
        let references = match &references {
            FieldValue::Array(array) => {
                if let Some(method) = array.properties().get_with_receiver("map", &references)? {
                    return Err(unsupported_map(method));
                }
                array
            }
            value => return Err(unsupported_map(value.model_property("map")?)),
        };
        let user = FieldValue::from(FieldMap::from(user.clone()));
        crate::request_runtime::concurrent::all(
            "User session refresh task",
            references.snapshot()?.into_iter().map(|reference| {
                let runtime = self.clone();
                let user = user.clone();
                async move {
                    let token = reference.model_property("token")?;
                    runtime
                        .refresh_cached_user_session(&token, &user, now)
                        .await
                }
            }),
        )
        .await
        .map(|_| ())
    }

    async fn refresh_cached_user_session(
        &self,
        token: &FieldValue,
        user: &FieldValue,
        now: chrono::DateTime<chrono::Utc>,
    ) -> AuthResult<()> {
        let Some(cached) = cache::decode(self.secondary()?.get_native(token).await?)? else {
            return Ok(());
        };
        let expires = cached
            .model_property("session")?
            .model_property("expiresAt")?;
        let seconds = SchemaValue::<FieldDate>::from_field(expires).cache_ttl(now)?;
        let envelope = FieldValue::from(FieldMap::from([
            ("session".into(), cached.model_property("session")?),
            ("user".into(), user.clone()),
        ]));
        self.secondary()?
            .set_native(token, &envelope.stringify_native()?, Some(seconds))
            .await?;
        Ok(())
    }
}

#[async_trait]
impl<S: AuthSchema> UserStore<S> for SecondaryStore<S> {
    fn supports_native_json(&self) -> bool {
        self.inner.supports_native_json()
    }
    async fn get_user_by_id_value(
        &self,
        id: &crate::FieldValue,
    ) -> AuthResult<Option<crate::wire::UserView>> {
        self.inner.get_user_by_id_value(id).await
    }

    async fn verify_user_and_revoke_unproven_access(
        &self,
        user_id: &str,
    ) -> AuthResult<Option<crate::wire::UserView>> {
        self.verify_user_and_revoke_unproven_access_value(&user_id.into())
            .await
    }

    async fn verify_user_and_revoke_unproven_access_value(
        &self,
        user_id: &FieldValue,
    ) -> AuthResult<Option<crate::wire::UserView>> {
        crate::store::revoke_unproven_account_access(self, user_id).await
    }
    async fn create_user_fields_optional(
        &self,
        input: crate::FieldMap,
    ) -> AuthResult<Option<crate::wire::UserView>> {
        self.inner.create_user_fields_optional(input).await
    }
    async fn create_user(&self, input: CreateUser) -> AuthResult<crate::wire::UserView> {
        self.inner.create_user(input).await
    }
    async fn get_user_by_id_field(
        &self,
        id: &crate::SchemaValue<String>,
    ) -> AuthResult<Option<crate::wire::UserView>> {
        self.inner.get_user_by_id_field(id).await
    }
    async fn get_user_by_id(&self, id: &str) -> AuthResult<Option<crate::wire::UserView>> {
        self.inner.get_user_by_id(id).await
    }
    async fn list_users_by_ids(
        &self,
        ids: &[String],
        limit: f64,
    ) -> AuthResult<Vec<crate::wire::UserView>> {
        self.inner.list_users_by_ids(ids, limit).await
    }
    async fn list_users_by_id_values(
        &self,
        ids: &[crate::FieldValue],
        limit: f64,
    ) -> AuthResult<Vec<crate::wire::UserView>> {
        self.inner.list_users_by_id_values(ids, limit).await
    }
    async fn get_user_with_accounts(
        &self,
        email: &str,
    ) -> AuthResult<Option<crate::store::UserAccounts>> {
        self.inner.get_user_with_accounts(email).await
    }
    async fn get_user_with_accounts_value(
        &self,
        email: &crate::FieldValue,
    ) -> AuthResult<Option<crate::store::UserAccounts>> {
        self.inner.get_user_with_accounts_value(email).await
    }
    async fn get_user_by_email(&self, email: &str) -> AuthResult<Option<crate::wire::UserView>> {
        self.inner.get_user_by_email(email).await
    }
    async fn get_user_by_username(
        &self,
        username: &str,
    ) -> AuthResult<Option<crate::wire::UserView>> {
        self.inner.get_user_by_username(username).await
    }
    async fn get_user_by_field_value(
        &self,
        field: &str,
        value: &crate::FieldValue,
    ) -> AuthResult<Option<crate::UserView>> {
        self.inner.get_user_by_field_value(field, value).await
    }
    async fn get_user_by_phone_number(
        &self,
        phone: &str,
    ) -> AuthResult<Option<crate::wire::UserView>> {
        self.inner.get_user_by_phone_number(phone).await
    }
    async fn update_user(&self, id: &str, update: UpdateUser) -> AuthResult<crate::wire::UserView> {
        let user = self.inner.update_user(id, update).await?;
        self.queue_user_session_refresh(Some(user.clone()), None)
            .await?;
        Ok(user)
    }
    async fn update_user_optional(
        &self,
        id: &str,
        update: UpdateUser,
    ) -> AuthResult<Option<crate::UserView>> {
        self.update_user_by_id_value(&crate::FieldValue::from(id), update)
            .await
    }
    async fn update_user_by_field_value(
        &self,
        field: &str,
        value: &crate::FieldValue,
        update: UpdateUser,
    ) -> AuthResult<Option<crate::UserView>> {
        let user = self
            .inner
            .update_user_by_field_value(field, value, update)
            .await?;
        self.queue_user_session_refresh(user.clone(), None).await?;
        Ok(user)
    }
    async fn delete_user(&self, id: &str) -> AuthResult<()> {
        self.delete_user_value(&id.into()).await
    }
    async fn delete_user_value(&self, id: &FieldValue) -> AuthResult<()> {
        if self.storage.is_none() {
            return self.inner.delete_user_value(id).await;
        }
        let references = self.references_value(id).await?;
        let removed = self
            .inner
            .delete_user_optional_value(id, self.database_sessions())
            .await?;
        if removed.is_some() {
            self.queue_cached_user_session_deletion_value(id.clone(), references, None)
                .await?;
        }
        Ok(())
    }
    async fn delete_user_optional(
        &self,
        id: &str,
        delete_database_sessions: bool,
    ) -> AuthResult<Option<crate::wire::UserView>> {
        self.delete_user_optional_value(&id.into(), delete_database_sessions)
            .await
    }
    async fn delete_user_optional_value(
        &self,
        id: &FieldValue,
        delete_database_sessions: bool,
    ) -> AuthResult<Option<crate::wire::UserView>> {
        self.inner
            .delete_user_optional_value(id, delete_database_sessions)
            .await
    }

    async fn list_users(
        &self,
        params: ListUsersParams,
    ) -> AuthResult<(Vec<crate::wire::UserView>, usize)> {
        self.inner.list_users(params).await
    }
}
