use super::*;
use crate::config::CookieCacheVersion;
use crate::field_value::{FieldObject, FieldObjectSource};
use crate::{HttpMethod, SessionView};
use std::sync::{Arc, Mutex};

type Events = Arc<Mutex<Vec<String>>>;

fn record(events: &Events, event: impl Into<String>) -> AuthResult<()> {
    events
        .lock()
        .map_err(|_| AuthError::internal("Cache trace poisoned"))?
        .push(event.into());
    Ok(())
}

struct Probe {
    model: &'static str,
    events: Events,
    error: Mutex<Option<AuthError>>,
}

impl FieldObjectSource for Probe {
    fn own_keys(&self) -> AuthResult<Vec<String>> {
        Ok(vec!["value".into(), "later".into()])
    }

    fn get(&self, name: &str) -> AuthResult<Option<FieldValue>> {
        record(&self.events, format!("{}.{name}", self.model))?;
        if let Some(error) = self
            .error
            .lock()
            .map_err(|_| AuthError::internal("Cache error poisoned"))?
            .take()
        {
            return Err(error);
        }
        Ok(Some(name.into()))
    }

    fn set(&self, _: String, _: FieldValue) -> AuthResult<Option<FieldValue>> {
        Err(AuthError::internal("Cache probes are immutable"))
    }

    fn delete(&self, _: &str) -> AuthResult<Option<FieldValue>> {
        Err(AuthError::internal("Cache probes are immutable"))
    }

    fn snapshot_fields(&self) -> AuthResult<FieldMap> {
        Err(AuthError::internal(
            "Cache probes require one property read at a time",
        ))
    }

    fn identity(&self) -> usize {
        std::ptr::from_ref(self) as usize
    }
}

fn data(session_payload: FieldValue, user_name: FieldValue) -> AuthResult<NativeSessionData> {
    Ok(NativeSessionData {
        session: SessionView::from_field_values(FieldMap::from([
            ("id".into(), "session".into()),
            ("token".into(), "token".into()),
            ("userId".into(), "owner".into()),
            ("payload".into(), session_payload),
        ]))?,
        user: FieldMap::from([("id".into(), "owner".into()), ("name".into(), user_name)]).into(),
    })
}

#[tokio::test]
async fn cache_failures_preserve_filter_version_json_order_and_original_errors() -> AuthResult<()> {
    for strategy in [
        CookieCacheStrategy::Compact,
        CookieCacheStrategy::Jwt,
        CookieCacheStrategy::Jwe,
    ] {
        for stage in [
            "session-getter",
            "user-getter",
            "version",
            "session-cycle",
            "user-cycle",
        ] {
            let events = Events::default();
            let message = "cookie cache original error".to_owned();
            let allocation = message.as_ptr() as usize;
            let error = Arc::new(Mutex::new(Some(AuthError::internal(message))));
            let mut cycles = Vec::new();
            let mut probe = |model: &'static str| -> AuthResult<FieldValue> {
                if stage.strip_suffix("-cycle") == Some(model) {
                    let object = FieldObject::from(FieldMap::new());
                    let _ = object.set("self", FieldValue::Object(object.clone()))?;
                    cycles.push(object.clone());
                    return Ok(FieldValue::Object(object));
                }
                let failure = if stage.strip_suffix("-getter") == Some(model) {
                    error
                        .lock()
                        .map_err(|_| AuthError::internal("Cache error poisoned"))?
                        .take()
                } else {
                    None
                };
                Ok(FieldValue::Object(FieldObject::from_source(Arc::new(
                    Probe {
                        model,
                        events: events.clone(),
                        error: Mutex::new(failure),
                    },
                ))))
            };
            let data = data(probe("session")?, probe("user")?)?;
            let mut config =
                AuthConfig::new("cookie-json-contract-secret-at-least-thirty-two-characters");
            config.session.additional_fields = Some(Default::default());
            config.session.cookie_cache = Some(CookieCacheConfig {
                enabled: Some(true),
                strategy: Some(strategy),
                version: CookieCacheVersion::dynamic({
                    let events = events.clone();
                    let error = error.clone();
                    move |_| {
                        let events = events.clone();
                        let error = error.clone();
                        async move {
                            record(&events, "version")?;
                            if stage == "version" {
                                return Err(error
                                    .lock()
                                    .map_err(|_| AuthError::internal("Cache error poisoned"))?
                                    .take()
                                    .ok_or_else(|| {
                                        AuthError::internal("Missing version failure")
                                    })?);
                            }
                            Ok("v2".into())
                        }
                    }
                }),
                ..Default::default()
            });
            let request = AuthRequest::new(HttpMethod::Get, "/get-session");
            let result = write(&request, &data, &config, false, None, false, None).await;
            for cycle in cycles {
                let _ = cycle.delete("self")?;
            }
            if stage.ends_with("cycle") {
                assert!(
                    matches!(result, Err(AuthError::TypeError(message)) if message == "Converting circular structure to JSON"),
                    "{stage}/{strategy:?}"
                );
            } else {
                assert!(
                    matches!(result, Err(AuthError::Internal(message)) if message == "cookie cache original error" && message.as_ptr() as usize == allocation),
                    "{stage}/{strategy:?}"
                );
            }
            let expected: &[&str] = match stage {
                "session-getter" => &["session.value"],
                "user-getter" => &["session.value", "session.later", "user.value"],
                "version" => &[
                    "session.value",
                    "session.later",
                    "user.value",
                    "user.later",
                    "version",
                ],
                "session-cycle" => &["user.value", "user.later", "version"],
                _ => &["session.value", "session.later", "version"],
            };
            assert_eq!(
                *events
                    .lock()
                    .map_err(|_| AuthError::internal("Cache trace poisoned"))?,
                expected,
                "{stage}/{strategy:?}"
            );
            assert!(request.take_response_headers()?.is_empty());
        }
    }
    Ok(())
}

#[tokio::test]
async fn payload_preserves_public_active_extension_and_omits_private_active() -> AuthResult<()> {
    for visible in [None, Some(FieldValue::from("public-active"))] {
        let mut data = data(FieldValue::Null, "Owner".into())?;
        data.session.active = true;
        if let Some(value) = &visible {
            let _ = data
                .session
                .additional_fields
                .insert("active".into(), value.clone());
        }
        let (payload, _) = payload(
            &data,
            &AuthConfig::default(),
            &CookieCacheConfig::default(),
            false,
        )
        .await?;
        let session = payload
            .get("session")
            .ok_or_else(|| AuthError::internal("Missing cache Session"))?;
        let mut expected = FieldMap::from([
            ("id".into(), FieldValue::from("session")),
            ("token".into(), "token".into()),
            ("userId".into(), "owner".into()),
            ("payload".into(), FieldValue::Null),
        ]);
        if visible.is_some() {
            let _ = expected.insert("active".into(), "public-active".into());
        }
        assert_eq!(
            session
                .as_object()
                .ok_or_else(|| AuthError::internal("Cache Session is not an object"))?
                .snapshot_fields()?,
            expected
        );
        assert!(data.session.active);
        assert_eq!(
            data.session.additional_fields.get("active"),
            visible.as_ref()
        );
    }
    Ok(())
}

#[tokio::test]
async fn compact_serializes_live_session_children_twice_after_version() -> AuthResult<()> {
    let events = Events::default();
    let child = FieldObject::from(FieldMap::from([("serial".into(), 0.0.into())]));
    let _ = child.set(
        "toJSON",
        crate::FieldFunction::contextual({
            let events = events.clone();
            move |receiver, arguments| {
                assert_eq!(arguments, &[FieldValue::from("payload")]);
                let serial = receiver
                    .model_property("serial")?
                    .as_f64()
                    .ok_or_else(|| AuthError::internal("Missing live serial"))?
                    + 1.0;
                let _ = receiver
                    .as_object()
                    .ok_or_else(|| AuthError::internal("Missing toJSON receiver"))?
                    .set("serial", serial.into())?;
                record(&events, format!("payload:{serial}"))?;
                Ok(FieldMap::from([("serial".into(), serial.into())]).into())
            }
        })
        .into(),
    )?;
    let data = data(FieldValue::Object(child.clone()), "Owner".into())?;
    let config = AuthConfig::new("cookie-live-contract-secret-at-least-thirty-two-characters");
    let cache = CookieCacheConfig {
        strategy: Some(CookieCacheStrategy::Compact),
        version: CookieCacheVersion::dynamic({
            let events = events.clone();
            move |_| {
                let events = events.clone();
                async move {
                    record(&events, "version")?;
                    Ok("live".into())
                }
            }
        }),
        ..Default::default()
    };
    let encoded = encode(&data, &config, &cache, false).await?;
    assert_eq!(child.get("serial")?, Some(2.0.into()));
    assert_eq!(
        *events
            .lock()
            .map_err(|_| AuthError::internal("Cache trace poisoned"))?,
        ["version", "payload:1", "payload:2"]
    );
    let envelope: Value = serde_json::from_slice(
        &URL_SAFE_NO_PAD
            .decode(encoded)
            .map_err(|error| AuthError::internal(error.to_string()))?,
    )?;
    assert_eq!(envelope["session"]["session"]["payload"]["serial"], 2);
    let mut signed = envelope["session"]
        .as_object()
        .ok_or_else(|| AuthError::internal("Missing signed payload"))?
        .clone();
    signed["session"]["payload"]["serial"] = 1.into();
    let _ = signed.insert("expiresAt".into(), envelope["expiresAt"].clone());
    let mut mac = Hmac::<Sha256>::new_from_slice(config.signing_secret().as_bytes())
        .map_err(|error| AuthError::internal(error.to_string()))?;
    mac.update(&serde_json::to_vec(&signed)?);
    assert_eq!(
        envelope["signature"],
        URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes())
    );
    Ok(())
}

#[tokio::test]
async fn clone_boundaries_reject_functions_before_to_json_and_preserve_absent_session_config()
-> AuthResult<()> {
    for strategy in [
        CookieCacheStrategy::Compact,
        CookieCacheStrategy::Jwt,
        CookieCacheStrategy::Jwe,
    ] {
        for declared in [false, true] {
            let events = Events::default();
            let value = FieldMap::from([(
                "toJSON".into(),
                crate::FieldFunction::contextual({
                    let events = events.clone();
                    move |_, _| {
                        record(&events, "toJSON")?;
                        Ok("encoded".into())
                    }
                })
                .into(),
            )]);
            let data = data(value.into(), "Owner".into())?;
            let mut config =
                AuthConfig::new("cookie-clone-contract-secret-at-least-thirty-two-characters");
            if declared {
                config.session.additional_fields = Some(Default::default());
            }
            let cache = CookieCacheConfig {
                strategy: Some(strategy),
                version: CookieCacheVersion::dynamic({
                    let events = events.clone();
                    move |_| {
                        let events = events.clone();
                        async move {
                            record(&events, "version")?;
                            Ok("native".into())
                        }
                    }
                }),
                ..Default::default()
            };
            let result = encode(&data, &config, &cache, false).await;
            let expected: &[&str] = if declared {
                assert!(matches!(result, Err(AuthError::DataClone)));
                &[]
            } else if matches!(strategy, CookieCacheStrategy::Compact) {
                assert!(result.is_ok());
                &["version", "toJSON", "toJSON"]
            } else {
                assert!(matches!(result, Err(AuthError::DataClone)));
                &["version"]
            };
            assert_eq!(
                *events
                    .lock()
                    .map_err(|_| AuthError::internal("Cache trace poisoned"))?,
                expected,
                "{strategy:?}/{declared}"
            );
        }
    }
    Ok(())
}
