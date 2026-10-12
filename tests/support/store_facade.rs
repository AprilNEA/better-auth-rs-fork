// Instantiate this facade in a private test module. Pass trait paths relative to the calling crate.
macro_rules! define_test_store {
    ($store_source:literal, $runtime_source:literal) => {
        use better_auth_core::store::*;
        use better_auth_core::types::*;
        use better_auth_core::{
            AuthConfig, AuthError, AuthResult, AuthSchema, FieldMap, FieldValue,
        };
        use std::sync::Arc;

        #[derive(Default)]
        pub(super) struct StoreInterceptions {
            pub credential_query_error: Option<FieldValue>,
            pub consume_verification_error_after: Option<FieldValue>,
            pub passkey_update_error_after: Option<FieldValue>,
            pub null_session: bool,
            pub missing_user: bool,
            pub session_overrides: FieldMap,
        }

        pub(super) struct TestStore<S: AuthSchema> {
            inner: Arc<dyn AuthStore<S>>,
            interceptions: Arc<StoreInterceptions>,
        }

        impl<S: AuthSchema> TestStore<S> {
            pub(super) fn new(
                inner: Arc<dyn AuthStore<S>>,
                interceptions: StoreInterceptions,
            ) -> Self {
                Self {
                    inner,
                    interceptions: Arc::new(interceptions),
                }
            }
        }

        #[better_auth_core::__test_store_forward($runtime_source)]
        impl<S: AuthSchema> RuntimeStore<S> for TestStore<S> {
            fn with_runtime(
                &self,
                config: Arc<AuthConfig>,
                hooks: Vec<Arc<dyn database_hooks::DatabaseHooks<S>>>,
                model_fields: better_auth_core::plugin_runtime::ModelFields,
            ) -> AuthResult<Arc<dyn AuthStore<S>>> {
                Ok(Arc::new(Self {
                    inner: self.inner.with_runtime(config, hooks, model_fields)?,
                    interceptions: self.interceptions.clone(),
                }))
            }
        }

        #[better_auth_core::__test_store_forward($store_source)]
        impl<S: AuthSchema> UserStore<S> for TestStore<S> {
            async fn get_user_by_id_field(
                &self,
                id: &better_auth_core::SchemaValue<String>,
            ) -> AuthResult<Option<better_auth_core::UserView>> {
                if self.interceptions.missing_user {
                    return Ok(None);
                }
                self.inner.get_user_by_id_field(id).await
            }
        }

        #[better_auth_core::__test_store_forward($store_source)]
        impl<S: AuthSchema> SessionStore<S> for TestStore<S> {
            async fn create_session_optional(
                &self,
                mut input: CreateSession,
            ) -> AuthResult<Option<better_auth_core::SessionView>> {
                if self.interceptions.null_session {
                    return Ok(None);
                }
                input
                    .additional_fields
                    .extend(self.interceptions.session_overrides.clone());
                self.inner.create_session_optional(input).await
            }
        }

        #[better_auth_core::__test_store_forward($store_source)]
        impl<S: AuthSchema> VerificationStore<S> for TestStore<S> {
            async fn consume_verification_by_identifier(
                &self,
                identifier: &str,
            ) -> AuthResult<Option<better_auth_core::VerificationView>> {
                let result = self
                    .inner
                    .consume_verification_by_identifier(identifier)
                    .await?;
                if let Some(error) = &self.interceptions.consume_verification_error_after {
                    return Err(AuthError::from_thrown(error.clone()));
                }
                Ok(result)
            }
        }

        #[better_auth_core::__test_store_forward($store_source)]
        impl<S: AuthSchema> PasskeyStore for TestStore<S> {
            async fn get_passkey_by_credential_id_value(
                &self,
                credential_id: &FieldValue,
            ) -> AuthResult<Option<Passkey>> {
                if let Some(error) = &self.interceptions.credential_query_error {
                    return Err(AuthError::from_thrown(error.clone()));
                }
                self.inner
                    .get_passkey_by_credential_id_value(credential_id)
                    .await
            }

            async fn update_passkey_authentication_optional(
                &self,
                id: &better_auth_core::SchemaValue<String>,
                input: UpdatePasskeyAuthentication,
            ) -> AuthResult<Option<Passkey>> {
                let result = self
                    .inner
                    .update_passkey_authentication_optional(id, input)
                    .await?;
                if let Some(error) = &self.interceptions.passkey_update_error_after {
                    return Err(AuthError::from_thrown(error.clone()));
                }
                Ok(result)
            }
        }

        #[better_auth_core::__test_store_forward($store_source)]
        impl<S: AuthSchema> AccountStore<S> for TestStore<S> {}

        #[better_auth_core::__test_store_forward($store_source)]
        impl<S: AuthSchema> OrganizationStore for TestStore<S> {}

        #[better_auth_core::__test_store_forward($store_source)]
        impl<S: AuthSchema> TeamStore for TestStore<S> {}

        #[better_auth_core::__test_store_forward($store_source)]
        impl<S: AuthSchema> OrganizationRoleStore for TestStore<S> {}

        #[better_auth_core::__test_store_forward($store_source)]
        impl<S: AuthSchema> MemberStore for TestStore<S> {}

        #[better_auth_core::__test_store_forward($store_source)]
        impl<S: AuthSchema> InvitationStore for TestStore<S> {}

        #[better_auth_core::__test_store_forward($store_source)]
        impl<S: AuthSchema> TwoFactorStore for TestStore<S> {}

        #[better_auth_core::__test_store_forward($store_source)]
        impl<S: AuthSchema> ApiKeyStore for TestStore<S> {}

        #[better_auth_core::__test_store_forward($store_source)]
        impl<S: AuthSchema> DeviceCodeStore for TestStore<S> {}

        #[better_auth_core::__test_store_forward($store_source)]
        impl<S: AuthSchema> WalletStore for TestStore<S> {}

        #[better_auth_core::__test_store_forward($store_source)]
        impl<S: AuthSchema> JwksStore for TestStore<S> {}

        #[better_auth_core::__test_store_forward($store_source)]
        impl<S: AuthSchema> RateLimitStore for TestStore<S> {}

        #[better_auth_core::__test_store_forward($store_source)]
        impl<S: AuthSchema> TransactionStore<S> for TestStore<S> {}
    };
}

pub(crate) use define_test_store;
