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
        let mut expected = serde_json::Map::from_iter([
            ("id".into(), Value::from("session")),
            ("token".into(), "token".into()),
            ("userId".into(), "owner".into()),
            ("payload".into(), Value::Null),
        ]);
        if visible.is_some() {
            let _ = expected.insert("active".into(), "public-active".into());
        }
        assert_eq!(session, &Value::Object(expected));
        assert!(data.session.active);
        assert_eq!(
            data.session.additional_fields.get("active"),
            visible.as_ref()
        );
    }
    Ok(())
}
