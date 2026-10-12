#![expect(
    clippy::unwrap_used,
    clippy::panic_in_result_fn,
    reason = "Native JWT regressions compare exact getter order, original failures, and persisted state."
)]

use super::super::native_test_support::{ObservedFields, Trace};
use super::*;
use better_auth_core::{
    AuthRecordFields, FieldDate, FieldFunction, FromFieldMap,
    session::NativeSessionData,
    store::{AuthStore, EphemeralStore, StatelessSchema},
    wire::SessionView,
};
use std::{
    collections::VecDeque,
    sync::{Arc, Mutex},
};

fn key_fields() -> AuthResult<FieldMap> {
    let private = JwtAlgorithm::EdDsa.generate(2048).map_err(jose_error)?;
    Ok(FieldMap::from([
        ("id".into(), "selected".into()),
        (
            "publicKey".into(),
            private
                .to_public_key()
                .map_err(jose_error)?
                .to_string()
                .into(),
        ),
        ("privateKey".into(), private.to_string().into()),
        ("createdAt".into(), FieldDate::from(Utc::now()).into()),
        ("expiresAt".into(), FieldValue::Null),
        ("alg".into(), "EdDSA".into()),
        ("crv".into(), "Ed25519".into()),
    ]))
}

fn keyring(value: FieldValue, trace: Arc<Trace>) -> JwtCallbacks<StatelessSchema> {
    JwtCallbacks::default().get_jwks_native(move |_| {
        trace.record("read");
        let value = value.clone();
        Box::pin(async move { Ok(value) })
    })
}

async fn context(
    plugin: &JwtPlugin,
    callbacks: JwtCallbacks<StatelessSchema>,
) -> AuthResult<AuthContext<StatelessSchema>> {
    let mut config = crate::plugins::test_helpers::create_test_config();
    config.telemetry.enabled = false;
    let config = Arc::new(config);
    let store: Arc<dyn AuthStore<StatelessSchema>> = Arc::new(EphemeralStore::new(config.clone()));
    let mut context =
        crate::plugins::test_helpers::initialize_test_context(config, store, &[plugin]).await?;
    context.extensions.insert(Arc::new(callbacks));
    Ok(context)
}

fn successive(
    key: &ObservedFields,
    property: &'static str,
    values: Vec<FieldValue>,
) -> AuthResult<()> {
    let values = Mutex::new(VecDeque::from(values));
    key.getter(
        property,
        FieldFunction::contextual(move |receiver, arguments| {
            assert!(arguments.is_empty());
            receiver.set_model_property("lastRead", property.into())?;
            values
                .lock()
                .unwrap()
                .pop_front()
                .ok_or_else(|| AuthError::internal("JWT read a getter more often than upstream"))
        }),
    )
}

fn pinned() -> JwtSigningOptions {
    JwtSigningOptions {
        key_id: Some("selected".into()),
        ..Default::default()
    }
}

#[tokio::test]
async fn signing_keeps_the_native_record_through_private_key_algorithm_and_id_consumption()
-> AuthResult<()> {
    let trace = Arc::new(Trace::default());
    let fields = key_fields()?;
    let private = fields.get("privateKey").unwrap().clone();
    let key = ObservedFields::new(fields, trace.clone(), Some(("publicKey", "unused".into())));
    key.getter(
        "privateKey",
        FieldFunction::contextual(move |receiver, arguments| {
            assert!(arguments.is_empty());
            receiver.set_model_property("id", "signed-id".into())?;
            Ok(private.clone())
        }),
    )?;
    let plugin = JwtPlugin::new().disable_private_key_encryption(true);
    let ctx = context(&plugin, keyring(vec![key.value()].into(), trace.clone())).await?;
    let token = plugin
        .sign_with_options(
            Map::from_iter([("sub".into(), "owner".into())]),
            &pinned(),
            &ctx,
        )
        .await?;
    assert_eq!(
        super::super::tests::header(&token),
        json!({"alg":"EdDSA", "kid":"signed-id"})
    );
    assert_eq!(
        *trace.events.lock().unwrap(),
        [
            "read",
            "get:id",
            "get:expiresAt",
            "get:privateKey",
            "get:alg",
            "get:id"
        ]
    );
    assert_eq!(key.fields.get("id")?, Some("signed-id".into()));
    Ok(())
}

#[tokio::test]
async fn pinned_algorithm_mismatch_rereads_the_getter_for_its_error_message() -> AuthResult<()> {
    for (second, actual) in [
        (
            FieldValue::Null,
            "unset (inherits keyPairConfig.alg \"EdDSA\")",
        ),
        (
            FieldValue::Undefined,
            "unset (inherits keyPairConfig.alg \"EdDSA\")",
        ),
        (FieldValue::from("changed"), "changed"),
    ] {
        let trace = Arc::new(Trace::default());
        let key = ObservedFields::new(key_fields()?, trace.clone(), None);
        successive(&key, "alg", vec!["RS256".into(), second])?;
        let plugin = JwtPlugin::new().disable_private_key_encryption(true);
        let ctx = context(&plugin, keyring(vec![key.value()].into(), trace.clone())).await?;
        let options = JwtSigningOptions {
            algorithm: Some(JwtAlgorithm::EdDsa),
            ..pinned()
        };
        let error = plugin
            .sign_with_options(Map::new(), &options, &ctx)
            .await
            .unwrap_err();
        assert!(
            matches!(error, AuthError::Config(message) if message == format!("signJWT: signingKeyId \"selected\" has alg \"{actual}\" but signingAlgorithm was set to \"EdDSA\"."))
        );
        assert_eq!(
            *trace.events.lock().unwrap(),
            ["read", "get:id", "get:alg", "get:alg"]
        );
        assert_eq!(key.fields.get("lastRead")?, Some("alg".into()));
    }
    Ok(())
}

#[tokio::test]
async fn signing_rereads_truthy_expiry_and_compares_the_second_dynamic_value() -> AuthResult<()> {
    for (second, expired) in [
        (
            FieldValue::from(FieldDate::from(Utc::now() + Duration::days(1))),
            false,
        ),
        (FieldValue::from(FieldDate::from_milliseconds(0.0)), true),
        (FieldValue::Undefined, false),
    ] {
        let trace = Arc::new(Trace::default());
        let key = ObservedFields::new(key_fields()?, trace.clone(), None);
        successive(&key, "expiresAt", vec![true.into(), second])?;
        let plugin = JwtPlugin::new().disable_private_key_encryption(true);
        let ctx = context(&plugin, keyring(vec![key.value()].into(), trace.clone())).await?;
        let result = plugin.sign_with_options(Map::new(), &pinned(), &ctx).await;
        let mut events = vec!["read", "get:id", "get:expiresAt", "get:expiresAt"];
        if expired {
            assert!(
                matches!(result, Err(AuthError::Config(message)) if message == "signJWT: requested signing key is expired and an explicit kid/alg was provided; not auto-minting a replacement. Rotate the key explicitly.")
            );
        } else {
            assert_eq!(super::super::tests::header(&result?)["kid"], "selected");
            events.extend(["get:privateKey", "get:alg", "get:id"]);
        }
        assert_eq!(*trace.events.lock().unwrap(), events);
    }
    Ok(())
}

#[tokio::test]
async fn signing_keeps_getter_mutations_and_original_errors_at_each_consumption_boundary()
-> AuthResult<()> {
    for property in ["privateKey", "alg", "id"] {
        let trace = Arc::new(Trace::default());
        let original: FieldValue = FieldMap::from([("failed".into(), property.into())]).into();
        let key = ObservedFields::new(key_fields()?, trace.clone(), None);
        let failure = original.clone();
        let reads = Mutex::new(0);
        key.getter(
            property,
            FieldFunction::contextual(move |receiver, _| {
                let mut reads = reads.lock().unwrap();
                *reads += 1;
                if property == "id" && *reads == 1 {
                    return Ok("selected".into());
                }
                receiver.set_model_property("progress", property.into())?;
                Err(AuthError::from_thrown(failure.clone()))
            }),
        )?;
        let plugin = JwtPlugin::new().disable_private_key_encryption(true);
        let ctx = context(&plugin, keyring(vec![key.value()].into(), trace.clone())).await?;
        let error = plugin
            .sign_with_options(Map::new(), &pinned(), &ctx)
            .await
            .unwrap_err();
        assert!(error.into_thrown_value()?.strict_equals(&original));
        assert_eq!(key.fields.get("progress")?, Some(property.into()));
        let mut events = vec!["read", "get:id", "get:expiresAt"];
        for consumed in ["privateKey", "alg", "id"] {
            events.push(match consumed {
                "privateKey" => "get:privateKey",
                "alg" => "get:alg",
                _ => "get:id",
            });
            if consumed == property {
                break;
            }
        }
        assert_eq!(*trace.events.lock().unwrap(), events);
    }
    Ok(())
}

#[tokio::test]
async fn discovery_filters_before_mapping_and_keeps_live_record_mutations_on_success_or_failure()
-> AuthResult<()> {
    for fails in [false, true] {
        let trace = Arc::new(Trace::default());
        let original: FieldValue = FieldMap::from([("failed".into(), "publicKey".into())]).into();
        let fields = || {
            FieldMap::from([
                ("id".into(), "selected".into()),
                ("expiresAt".into(), FieldValue::Null),
                ("alg".into(), "stored".into()),
                ("crv".into(), "stored-curve".into()),
                (
                    "publicKey".into(),
                    "{\"alg\":\"published\",\"crv\":null,\"kid\":\"embedded\",\"marker\":\"kept\"}"
                        .into(),
                ),
                ("privateKey".into(), "secret".into()),
            ])
        };
        let first = ObservedFields::new(
            fields(),
            trace.clone(),
            Some(("privateKey", original.clone())),
        );
        let second = ObservedFields::new(
            fields(),
            trace.clone(),
            Some(("privateKey", original.clone())),
        );
        successive(
            &first,
            "expiresAt",
            vec![
                true.into(),
                FieldDate::from(Utc::now() + Duration::days(1)).into(),
            ],
        )?;
        let second_fields = second.fields.clone();
        let public = first.fields.get("publicKey")?.unwrap();
        let failure = original.clone();
        first.getter(
            "publicKey",
            FieldFunction::contextual(move |_, _| {
                let _ = second_fields.set("id", "changed".into())?;
                if fails {
                    return Err(AuthError::from_thrown(failure.clone()));
                }
                Ok(public.clone())
            }),
        )?;
        let plugin = JwtPlugin::new();
        let ctx = context(
            &plugin,
            keyring(vec![first.value(), second.value()].into(), trace.clone()),
        )
        .await?;
        let result = plugin
            .jwks(&EndpointContext::native(None, None, FieldValue::Null, &ctx))
            .await;
        let mut events = vec![
            "read",
            "get:expiresAt",
            "get:expiresAt",
            "get:expiresAt",
            "get:alg",
            "get:crv",
            "get:publicKey",
        ];
        if fails {
            assert!(
                result
                    .unwrap_err()
                    .into_thrown_value()?
                    .strict_equals(&original)
            );
        } else {
            assert_eq!(
                result?.body.json()?,
                Some(json!({"keys":[
                    {"alg":"published","crv":null,"kid":"selected","marker":"kept"},
                    {"alg":"published","crv":null,"kid":"changed","marker":"kept"}
                ]}))
            );
            events.extend(["get:id", "get:alg", "get:crv", "get:publicKey", "get:id"]);
        }
        assert_eq!(*trace.events.lock().unwrap(), events);
        assert_eq!(second.fields.get("id")?, Some("changed".into()));
    }
    Ok(())
}

#[tokio::test]
async fn native_create_readback_preserves_the_write_and_is_only_consumed_by_signing()
-> AuthResult<()> {
    for discovery in [false, true] {
        let trace = Arc::new(Trace::default());
        let original: FieldValue = FieldMap::from([("failed".into(), "readback".into())]).into();
        let readback = Arc::new(Mutex::new(None::<Arc<ObservedFields>>));
        let reads = trace.clone();
        let writes = trace.clone();
        let returned = readback.clone();
        let failure = original.clone();
        let callbacks = JwtCallbacks::<StatelessSchema>::default()
            .get_jwks_native(move |endpoint| {
                reads.record("read");
                Box::pin(async move { endpoint.auth.database.list_jwk_values().await })
            })
            .create_jwk_native(move |input, endpoint| {
                let trace = writes.clone();
                let returned = returned.clone();
                let failure = failure.clone();
                Box::pin(async move {
                    let stored = endpoint.auth.database.create_jwk(input).await?;
                    trace.record("write");
                    let row = ObservedFields::new(stored.field_values()?, trace, None);
                    row.getter(
                        "privateKey",
                        FieldFunction::contextual(move |receiver, _| {
                            receiver.set_model_property("failedRead", true.into())?;
                            Err(AuthError::from_thrown(failure.clone()))
                        }),
                    )?;
                    *returned.lock().unwrap() = Some(row.clone());
                    Ok(row.value())
                })
            });
        let plugin = JwtPlugin::new().disable_private_key_encryption(true);
        let ctx = context(&plugin, callbacks).await?;
        if discovery {
            let response = plugin
                .jwks(&EndpointContext::native(None, None, FieldValue::Null, &ctx))
                .await?;
            assert_eq!(
                response.body.json()?.unwrap()["keys"]
                    .as_array()
                    .unwrap()
                    .len(),
                1
            );
            assert_eq!(*trace.events.lock().unwrap(), ["read", "write", "read"]);
        } else {
            let error = plugin.sign(Map::new(), &ctx).await.unwrap_err();
            assert!(error.into_thrown_value()?.strict_equals(&original));
            assert_eq!(
                *trace.events.lock().unwrap(),
                ["read", "read", "write", "get:privateKey"]
            );
        }
        assert_eq!(ctx.database.list_jwks().await?.len(), 1);
        assert_eq!(
            readback
                .lock()
                .unwrap()
                .as_ref()
                .unwrap()
                .fields
                .get("failedRead")?,
            (!discovery).then(|| true.into())
        );
    }
    Ok(())
}

#[tokio::test]
async fn session_subject_reads_array_function_and_date_own_ids_without_calling_the_user()
-> AuthResult<()> {
    let trace = Arc::new(Trace::default());
    let plugin = JwtPlugin::new().disable_private_key_encryption(true);
    let ctx = context(
        &plugin,
        keyring(vec![FieldValue::from(key_fields()?)].into(), trace.clone()),
    )
    .await?;
    for user in [
        FieldValue::from(Vec::<FieldValue>::new()),
        FieldFunction::contextual(|_, _| Err(AuthError::internal("JWT must not invoke the User")))
            .into(),
        FieldDate::from_milliseconds(0.0).into(),
    ] {
        user.set_model_property("id", "native-owner".into())?;
        user.set_model_property("marker", "kept".into())?;
        let session = NativeSessionData {
            user,
            session: SessionView::from_field_values(FieldMap::from([
                ("id".into(), "session".into()),
                ("token".into(), "session-token".into()),
                ("userId".into(), "native-owner".into()),
            ]))?,
        };
        let token = plugin
            .sign_session(
                Some(session),
                &EndpointContext::native(None, None, FieldValue::Null, &ctx),
            )
            .await?;
        let payload = plugin.verify(&token, None, &ctx).await?.unwrap();
        assert_eq!(payload["sub"], "native-owner");
        assert_eq!(payload["marker"], "kept");
    }
    for (user, message) in [
        (
            FieldValue::Null,
            "null is not an object (evaluating 'ctx.context.session.user.id')",
        ),
        (
            FieldValue::Undefined,
            "Cannot read properties of undefined (reading 'id')",
        ),
    ] {
        trace.events.lock().unwrap().clear();
        let session = NativeSessionData {
            user,
            session: SessionView::from_field_values(FieldMap::new())?,
        };
        let result = plugin
            .sign_session(
                Some(session),
                &EndpointContext::native(None, None, FieldValue::Null, &ctx),
            )
            .await;
        assert!(matches!(result, Err(AuthError::TypeError(actual)) if actual == message));
        assert!(trace.events.lock().unwrap().is_empty());
    }
    Ok(())
}
