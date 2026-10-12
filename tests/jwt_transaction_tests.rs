#![cfg(feature = "seaorm2")]
#![allow(
    clippy::unwrap_used,
    reason = "integration fixtures fail immediately on setup or assertion errors"
)]

use better_auth::plugins::JwtPlugin;
use better_auth::{AuthBuilder, AuthConfig, AuthError, AuthResult, AuthSchema, BetterAuth};
use better_auth_core::{
    AuthRequest, AuthUser, CreateSession, CreateUser, HttpMethod,
    config::{CookieCacheConfig, CookieCacheStrategy},
    store::transaction,
};
use better_auth_seaorm::store::__private_test_support::{bundled_schema::BundledSchema, migrator};
use better_auth_seaorm::{Database, SeaOrmStore};
use std::sync::Arc;

fn config() -> AuthConfig {
    let mut config = AuthConfig::new("transaction-cookie-secret-at-least-32-characters");
    config.session.cookie_cache = Some(CookieCacheConfig {
        enabled: Some(true),
        strategy: Some(CookieCacheStrategy::Jwt),
        ..Default::default()
    });
    config
}

async fn assert_signing_transaction<S: AuthSchema>(auth: BetterAuth<S>) -> AuthResult<()> {
    for rollback in [true, false] {
        let request = AuthRequest::new(HttpMethod::Post, "/sign-up/email");
        let request_in_tx = request.clone();
        let manager = auth.context().session_manager();
        let context = auth.context().clone();
        let result: AuthResult<()> = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            transaction(auth.store().as_ref(), move |tx| {
                Box::pin(async move {
                    let user = tx
                        .create_user(
                            CreateUser::new()
                                .with_email("transaction@example.com")
                                .with_name("Transaction"),
                        )
                        .await?;
                    let session = tx
                        .create_session(CreateSession {
                            inherited_fields: Default::default(),
                            additional_fields: Default::default(),
                            user_id: user.id().into_owned(),
                            expires_at: (chrono::Utc::now() + chrono::Duration::hours(1)).into(),
                            ip_address: None,
                            user_agent: None,
                            impersonated_by: None,
                            active_organization_id: None,
                        })
                        .await?;
                    let data = manager.internal_data(&user, &session).await?;
                    let mut endpoint =
                        better_auth::plugins::endpoint_context::EndpointContext::native(
                            None,
                            None,
                            better_auth_core::FieldValue::Null,
                            &context,
                        );
                    endpoint.transaction = Some(tx);
                    let _ = endpoint
                        .jwt()?
                        .sign(serde_json::from_value(
                            serde_json::json!({"sub":"transaction-user"}),
                        )?)
                        .await?;
                    manager
                        .set_session_cookie_in_transaction(&request_in_tx, data, Some(false), tx)
                        .await?;
                    assert_eq!(tx.list_jwks().await?.len(), 1);
                    if rollback {
                        Err(AuthError::bad_request("Abort after signing"))
                    } else {
                        Ok(())
                    }
                })
            }),
        )
        .await
        .map_err(|error| {
            AuthError::internal(format!(
                "Signing must use the active connection without database re-entry: {error}"
            ))
        })?;
        assert_eq!(result.is_err(), rollback);
        assert_eq!(
            auth.store().list_jwks().await.unwrap().len(),
            usize::from(!rollback)
        );
        assert_eq!(
            auth.store()
                .get_user_by_email("transaction@example.com")
                .await
                .unwrap()
                .is_some(),
            !rollback
        );
        let cookies = request.take_response_headers().unwrap();
        assert!(
            cookies
                .get_all("set-cookie")
                .any(|cookie| cookie.starts_with("better-auth.session_data="))
        );
    }
    Ok(())
}

#[tokio::test]
async fn sqlite_cookie_and_native_keys_share_the_session_transaction_and_rollback() -> AuthResult<()>
{
    let config = config();
    let database = Database::connect("sqlite::memory:").await.unwrap();
    migrator::run_migrations(&database).await.unwrap();
    let store = SeaOrmStore::<BundledSchema>::new(Arc::new(config.clone()), database);
    let auth = AuthBuilder::new(config)
        .store(store)
        .plugin(JwtPlugin::new().session_cookie_cache(true))
        .build()
        .await
        .unwrap();
    assert_signing_transaction(auth).await
}

#[tokio::test]
async fn ephemeral_cookie_and_native_keys_share_the_session_transaction_and_rollback()
-> AuthResult<()> {
    let auth = BetterAuth::stateless(config())
        .plugin(JwtPlugin::new().session_cookie_cache(true))
        .build()
        .await
        .unwrap();
    assert_signing_transaction(auth).await
}

fn transaction_callbacks<S: AuthSchema>(
    events: Arc<std::sync::Mutex<Vec<&'static str>>>,
) -> better_auth::plugins::JwtCallbacks<S> {
    let read_events = events.clone();
    better_auth::plugins::JwtCallbacks::default()
        .get_jwks(move |endpoint| {
            let events = read_events.clone();
            Box::pin(async move {
                let tx = endpoint.transaction.ok_or_else(|| {
                    AuthError::internal("JWT reads must retain the active transaction")
                })?;
                assert!(
                    tx.get_user_by_email("transaction@example.com")
                        .await?
                        .is_some(),
                    "callback must see the uncommitted user"
                );
                events.lock().unwrap().push("get");
                tx.list_jwks().await.map(Some)
            })
        })
        .create_jwk(move |key, endpoint| {
            let events = events.clone();
            Box::pin(async move {
                let tx = endpoint.transaction.ok_or_else(|| {
                    AuthError::internal("JWT writes must retain the active transaction")
                })?;
                assert!(
                    tx.get_user_by_email("transaction@example.com")
                        .await?
                        .is_some(),
                    "callback must see the uncommitted user"
                );
                events.lock().unwrap().push("create");
                tx.create_jwk(key).await.map(Some)
            })
        })
}

#[tokio::test]
async fn sqlite_custom_jwt_callbacks_share_the_session_transaction_and_rollback() {
    let config = config();
    let database = Database::connect("sqlite::memory:").await.unwrap();
    migrator::run_migrations(&database).await.unwrap();
    let store = SeaOrmStore::<BundledSchema>::new(Arc::new(config.clone()), database);
    let events = Arc::new(std::sync::Mutex::new(Vec::new()));
    let auth = AuthBuilder::new(config)
        .store(store)
        .plugin(
            JwtPlugin::new()
                .session_cookie_cache(true)
                .callbacks(transaction_callbacks(events.clone())),
        )
        .build()
        .await
        .unwrap();
    assert_signing_transaction(auth).await.unwrap();
    assert_eq!(
        *events.lock().unwrap(),
        ["get", "get", "create", "get", "get", "get", "create", "get"]
    );
}

#[tokio::test]
async fn ephemeral_custom_jwt_callbacks_share_the_session_transaction_and_rollback() {
    let events = Arc::new(std::sync::Mutex::new(Vec::new()));
    let auth = BetterAuth::stateless(config())
        .plugin(
            JwtPlugin::new()
                .session_cookie_cache(true)
                .callbacks(transaction_callbacks(events.clone())),
        )
        .build()
        .await
        .unwrap();
    assert_signing_transaction(auth).await.unwrap();
    assert_eq!(
        *events.lock().unwrap(),
        ["get", "get", "create", "get", "get", "get", "create", "get"]
    );
}

#[tokio::test]
async fn native_sign_endpoint_preserves_child_identity_undefined_and_custom_result()
-> AuthResult<()> {
    use better_auth::plugins::JwtAlgorithm;
    use better_auth_core::{FieldMap, FieldValue};
    use std::sync::atomic::{AtomicUsize, Ordering};
    let child: FieldValue = FieldMap::from([("retained".into(), true.into())]).into();
    let payload: FieldValue = FieldMap::from([
        ("child".into(), child.clone()),
        ("absent".into(), FieldValue::Undefined),
    ])
    .into();
    let returned: FieldValue = FieldMap::from([("native".into(), true.into())]).into();
    let result = returned.clone();
    let calls = Arc::new(AtomicUsize::new(0));
    let sign_calls = calls.clone();
    let sign_input = payload.clone();
    let sign_child = child.clone();
    let plugin = JwtPlugin::new()
        .remote_url("http://jwt-native-callbacks.test/keys".to_owned())
        .algorithm(JwtAlgorithm::EdDsa)
        .custom_sign_native(Arc::new(move |claims, header, selection| {
            let input = sign_input.clone();
            let child = sign_child.clone();
            let returned = result.clone();
            let calls = sign_calls.clone();
            Box::pin(async move {
                calls.fetch_add(1, Ordering::SeqCst);
                assert!(!claims.strict_equals(&input));
                assert!(claims.model_property("child")?.strict_equals(&child));
                assert!(
                    claims
                        .as_object()
                        .unwrap()
                        .own_property_descriptor("absent")?
                        .is_some()
                );
                assert!(claims.model_property("absent")?.is_undefined());
                assert!(header.is_undefined());
                assert_eq!(
                    selection.enumerable_fields()?,
                    FieldMap::from([
                        ("signingKeyId".into(), FieldValue::Undefined),
                        ("signingAlgorithm".into(), FieldValue::Undefined),
                    ])
                );
                Ok(returned)
            })
        }));
    let auth = BetterAuth::stateless(
        AuthConfig::new("jwt-native-callbacks-secret-at-least-thirty-two-characters")
            .base_url("http://jwt-native-callbacks.test"),
    )
    .plugin(plugin)
    .build()
    .await?;
    let token = auth.jwt()?.sign_value(payload.clone()).await?;
    assert!(token.strict_equals(&returned));
    assert_eq!(
        payload.enumerable_fields()?,
        FieldMap::from([
            ("child".into(), child),
            ("absent".into(), FieldValue::Undefined),
        ])
    );
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    Ok(())
}
