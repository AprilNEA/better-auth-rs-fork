#![expect(
    clippy::panic_in_result_fn,
    reason = "The native JWT contract asserts truthiness, callback order, error class, and zero persistence."
)]

use better_auth::{AuthConfig, AuthError, AuthResult, BetterAuth, plugins::JwtPlugin};
use better_auth_core::{
    FieldFunction, FieldMap, FieldObject, FieldValue,
    field_value::{FieldObjectSource, FieldPropertyDescriptor},
};
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicUsize, Ordering},
};

struct ChangingSigner {
    events: Arc<Mutex<Vec<&'static str>>>,
    reads: AtomicUsize,
    next: FieldValue,
}

impl FieldObjectSource for ChangingSigner {
    fn own_keys(&self) -> AuthResult<Vec<String>> {
        Ok(vec!["sign".into()])
    }

    fn own_property_descriptor(&self, name: &str) -> AuthResult<Option<FieldPropertyDescriptor>> {
        Ok((name == "sign").then_some(FieldPropertyDescriptor { enumerable: true }))
    }

    fn get(&self, name: &str) -> AuthResult<Option<FieldValue>> {
        if name != "sign" {
            return Ok(None);
        }
        let first = self.reads.fetch_add(1, Ordering::SeqCst) == 0;
        self.events
            .lock()
            .map_err(|_| AuthError::internal("Signer trace lock poisoned"))?
            .push(if first { "sign.get:1" } else { "sign.get:2" });
        Ok(Some(if first {
            false.into()
        } else {
            self.next.clone()
        }))
    }

    fn set(&self, _: String, _: FieldValue) -> AuthResult<Option<FieldValue>> {
        Err(AuthError::internal("Signing must not mutate JWT options"))
    }
    fn delete(&self, _: &str) -> AuthResult<Option<FieldValue>> {
        Err(AuthError::internal("Signing must not remove JWT options"))
    }
    fn snapshot_fields(&self) -> AuthResult<FieldMap> {
        Err(AuthError::internal(
            "Signing must not snapshot nested JWT options",
        ))
    }
    fn identity(&self) -> usize {
        std::ptr::from_ref(self).addr()
    }
}

#[tokio::test]
async fn changing_sign_truthiness_rejects_the_null_resolved_key_before_storage() -> AuthResult<()> {
    for callable in [true, false] {
        let mut config = AuthConfig::new("native-jwt-null-key-secret-at-least-32-characters");
        config.base_url = "http://jwt-native-null-key.test".into();
        config.telemetry.enabled = false;
        let auth = BetterAuth::stateless(config)
            .plugin(JwtPlugin::new())
            .build()
            .await?;
        let events = Arc::new(Mutex::new(Vec::new()));
        let observed = events.clone();
        let next = if callable {
            FieldFunction::contextual(move |_, _| {
                observed
                    .lock()
                    .map_err(|_| AuthError::internal("Signer trace lock poisoned"))?
                    .push("sign.call");
                Err(AuthError::internal(
                    "Resolving a delegated signing key must not call the signer",
                ))
            })
            .into()
        } else {
            FieldMap::from([("delegated".into(), true.into())]).into()
        };
        let signer = Arc::new(ChangingSigner {
            events: events.clone(),
            reads: AtomicUsize::new(0),
            next,
        });
        let result = auth
            .jwt()?
            .sign_value_with_overrides(
                FieldMap::from([("iat".into(), 10.0.into()), ("exp".into(), 70.0.into())]).into(),
                FieldMap::from([(
                    "jwt".into(),
                    FieldObject::from_source(signer.clone()).into(),
                )])
                .into(),
            )
            .await;
        let error = match result {
            Err(error) => error,
            Ok(_) => {
                return Err(AuthError::internal(
                    "Null resolved keys must reject signing",
                ));
            }
        };
        assert!(!error.is_api_error()?);
        let native = error.into_thrown_value()?;
        assert_eq!(native.model_property("name")?, "TypeError".into());
        assert_eq!(
            native.model_property("message")?,
            "Cannot destructure property 'alg' from null or undefined value".into(),
        );
        assert_eq!(signer.reads.load(Ordering::SeqCst), 2);
        assert_eq!(
            *events
                .lock()
                .map_err(|_| AuthError::internal("Signer trace lock poisoned"))?,
            ["sign.get:1", "sign.get:2"]
        );
        assert!(auth.store().list_jwk_records().await?.is_empty());
    }
    Ok(())
}
