#![expect(
    clippy::unwrap_used,
    clippy::panic_in_result_fn,
    reason = "Frozen JWT contracts require exact callback binding and complete source observations."
)]

use super::*;
use crate::plugins::test_helpers::native_sort_contract::{Harness, assert_case, jwk_cases};
use better_auth_core::{
    SchemaValue,
    store::{AuthStore, EphemeralStore, JwksStore, StatelessSchema},
};
use std::sync::{Arc, Weak};

struct KeyringStore {
    harness: Harness,
    owner: Weak<Self>,
}

#[async_trait::async_trait]
impl JwksStore for KeyringStore {
    async fn list_jwk_values(&self) -> AuthResult<FieldValue> {
        assert!(std::ptr::eq(self, self.owner.upgrade().unwrap().as_ref()));
        self.harness.read_keyring(
            "default",
            FieldMap::from([("model".into(), "jwks".into())]).into(),
        )
    }

    async fn create_jwk_record(&self, _: FieldMap) -> AuthResult<Option<FieldMap>> {
        Err(AuthError::internal("Selection must not create a key"))
    }
    async fn get_jwk_record(&self, _: &SchemaValue<String>) -> AuthResult<Option<FieldMap>> {
        Err(AuthError::internal(
            "Latest selection must not read one key",
        ))
    }
    async fn update_jwk_record(
        &self,
        _: &SchemaValue<String>,
        _: FieldMap,
    ) -> AuthResult<Option<FieldMap>> {
        Err(AuthError::internal("Selection must not update a key"))
    }
    async fn delete_jwk_record(&self, _: &SchemaValue<String>) -> AuthResult<()> {
        Err(AuthError::internal("Selection must not delete a key"))
    }
    async fn list_jwk_records(&self) -> AuthResult<Vec<FieldMap>> {
        Err(AuthError::internal(
            "Native keyring selection must retain logical handles",
        ))
    }
}

#[tokio::test]
async fn jwk_native_sort_replays_real_keyring_reads_and_complete_native_graphs() -> AuthResult<()> {
    let config = Arc::new(crate::plugins::test_helpers::create_test_config());
    let database: Arc<dyn AuthStore<StatelessSchema>> =
        Arc::new(EphemeralStore::new(config.clone()));
    let context = Arc::new(AuthContext::new(config, database)?);
    for case in jwk_cases() {
        let harness = if case["access"] == "getters" {
            Harness::new_getters(case)?
        } else {
            Harness::new(case)?
        };
        let before = harness.before()?;
        let store = Arc::new_cyclic(|owner| KeyringStore {
            harness: harness.clone(),
            owner: owner.clone(),
        });
        let marker: FieldValue = FieldMap::from([("marker".into(), "sort-context".into())]).into();
        let endpoint = Box::new(EndpointContext::native(
            None,
            None,
            marker.clone(),
            &context,
        ));
        let expected_endpoint = std::ptr::from_ref(endpoint.as_ref()) as usize;
        let expected_context = context.clone();
        let observed = harness.clone();
        let callbacks =
            JwtCallbacks::<StatelessSchema>::default().get_jwks_native(move |endpoint| {
                assert_eq!(std::ptr::from_ref(endpoint) as usize, expected_endpoint);
                assert!(std::ptr::eq(endpoint.auth, expected_context.as_ref()));
                assert!(endpoint.body.strict_equals(&marker));
                let result = observed.read_keyring("custom", endpoint.body.clone());
                Box::pin(async move { result })
            });
        let mut fields = FieldMap::new();
        if case["lane"] == "custom" {
            let _ = fields.insert("adapter".into(), callbacks.to_native());
        }
        let options = overrides::NativeOptions(fields.into());
        let keyring = adapter::Keyring::new(store.as_ref(), &options, &endpoint);
        let result = keyring
            .latest(case["algorithm"].as_str().map(FieldValue::from))
            .await;
        assert_case(&harness.finish(before, result)?, case);
    }
    Ok(())
}
