//! Native code exchange regressions use the root shapes and effects captured from Better Auth 1.7.6.

#![expect(
    clippy::unwrap_used,
    clippy::panic_in_result_fn,
    reason = "Regression assertions inspect original handles, ordered callbacks, and captured failures."
)]

use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use better_auth_core::{
    FieldArray, FieldFunction, FieldMap, FieldObject,
    field_value::{FieldObjectSource, FieldPropertyDescriptor},
};

use super::super::{
    GenericOAuthConfig, OAuthTokenHandler, providers::OAuthProvider, resolved::ResolvedGenericOAuth,
};
use super::*;

struct Exchange {
    input: FieldValue,
    result: FieldValue,
    error: Option<FieldValue>,
    calls: Mutex<usize>,
}

#[async_trait]
impl OAuthTokenHandler for Exchange {
    async fn get_token_native(&self, input: &FieldValue) -> AuthResult<FieldValue> {
        assert!(input.strict_equals(&self.input));
        *self.calls.lock().unwrap() += 1;
        if let Some(error) = &self.error {
            return Err(AuthError::from_thrown(error.clone()));
        }
        Ok(self.result.clone())
    }
}

fn provider(exchange: Arc<Exchange>, expiry: Option<f64>) -> ResolvedProvider {
    ResolvedProvider {
        config: OAuthProvider::google("client", "secret"),
        generic: Some(ResolvedGenericOAuth {
            config: GenericOAuthConfig {
                get_token: Some(exchange),
                access_token_expires_in: expiry,
                ..Default::default()
            },
            issuer: None,
            is_oidc: false,
            verifier: None,
        }),
    }
}

fn input(verifier: Option<FieldValue>) -> FieldValue {
    let mut fields = FieldMap::from([("code".into(), "native-code".into())]);
    if let Some(verifier) = verifier {
        let _ = fields.insert("codeVerifier".into(), verifier);
    }
    let _ = fields.insert("deviceId".into(), FieldValue::Undefined);
    let _ = fields.insert(
        "redirectURI".into(),
        "https://oauth-native-token.test/api/auth/callback/native".into(),
    );
    fields.into()
}

fn value(kind: &str) -> FieldValue {
    match kind {
        "undefined" => FieldValue::Undefined,
        "null" => FieldValue::Null,
        "false" => false.into(),
        "zero" => 0.into(),
        "nan" => f64::NAN.into(),
        "empty" => "".into(),
        "string" => "native-string".into(),
        "true" => true.into(),
        "number" => 7.into(),
        "array" => vec![
            "first".into(),
            FieldValue::Undefined,
            FieldMap::from([("ownUndefined".into(), FieldValue::Undefined)]).into(),
        ]
        .into(),
        "date" => FieldDate::from_milliseconds(1_893_553_445_000.0).into(),
        "invalid-date" => FieldDate::invalid().into(),
        "function" => FieldFunction::contextual(|_, _| Ok("token-function-result".into())).into(),
        _ => FieldMap::from([
            ("accessToken".into(), "access".into()),
            ("ownUndefined".into(), FieldValue::Undefined),
        ])
        .into(),
    }
}

#[tokio::test]
async fn native_exchange_preserves_verifier_presence_type_and_input_identity() -> AuthResult<()> {
    for kind in [
        "omitted",
        "undefined",
        "null",
        "false",
        "zero",
        "nan",
        "empty",
        "string",
        "date",
        "invalid-date",
        "array",
        "object",
    ] {
        let request = input((kind != "omitted").then(|| value(kind)));
        let token = value("object");
        let exchange = Arc::new(Exchange {
            input: request.clone(),
            result: token.clone(),
            error: None,
            calls: Mutex::new(0),
        });
        let result = validate_authorization_code_native_via_provider(
            &provider(exchange.clone(), None),
            &request,
        )
        .await?;
        assert!(result.strict_equals(&token), "{kind}");
        assert_eq!(*exchange.calls.lock().unwrap(), 1);
        assert_eq!(request.has_property("codeVerifier")?, kind != "omitted");
        assert_eq!(
            request.as_object().unwrap().own_keys()?,
            if kind == "omitted" {
                vec!["code", "deviceId", "redirectURI"]
            } else {
                vec!["code", "codeVerifier", "deviceId", "redirectURI"]
            }
        );
        assert!(request.model_property("deviceId")?.is_undefined());
    }
    Ok(())
}

#[tokio::test]
async fn native_exchange_keeps_root_values_until_expiry_property_access() -> AuthResult<()> {
    for kind in [
        "undefined",
        "null",
        "false",
        "zero",
        "nan",
        "empty",
        "string",
        "true",
        "number",
        "array",
        "date",
        "function",
        "object",
    ] {
        for expiry in [None, Some(30.0)] {
            let request = input(Some("verifier".into()));
            let token = value(kind);
            let exchange = Arc::new(Exchange {
                input: request.clone(),
                result: token.clone(),
                error: None,
                calls: Mutex::new(0),
            });
            let before = Utc::now().timestamp_millis();
            let result = validate_authorization_code_native_via_provider(
                &provider(exchange.clone(), expiry),
                &request,
            )
            .await;
            let after = Utc::now().timestamp_millis();
            assert_eq!(*exchange.calls.lock().unwrap(), 1);
            if matches!(kind, "undefined" | "null") {
                assert!(
                    matches!(result, Err(AuthError::TypeError(message)) if message == format!("{kind} is not an object (evaluating 'tokens.accessTokenExpiresAt')"))
                );
            } else if expiry.is_some() && !matches!(kind, "array" | "date" | "function" | "object")
            {
                assert!(
                    matches!(result, Err(AuthError::TypeError(message)) if message == "Attempted to assign to readonly property.")
                );
            } else {
                let result = result?;
                assert!(
                    result.strict_equals(&token)
                        || kind == "nan" && result.as_f64().is_some_and(f64::is_nan)
                );
                if expiry.is_some() {
                    let actual = result.model_property("accessTokenExpiresAt")?;
                    let milliseconds = actual.as_date().unwrap().milliseconds();
                    assert!(
                        milliseconds >= (before + 30_000) as f64
                            && milliseconds <= (after + 30_000) as f64
                    );
                }
            }
        }
    }
    Ok(())
}

struct ExpirySource {
    mode: &'static str,
    fields: Mutex<FieldMap>,
    receiver: Mutex<Option<FieldValue>>,
    events: Mutex<Vec<&'static str>>,
    original: FieldValue,
}

impl FieldObjectSource for ExpirySource {
    fn own_keys(&self) -> AuthResult<Vec<String>> {
        Ok(self.fields.lock().unwrap().keys().cloned().collect())
    }

    fn own_property_descriptor(&self, name: &str) -> AuthResult<Option<FieldPropertyDescriptor>> {
        Ok(self
            .fields
            .lock()
            .unwrap()
            .contains_key(name)
            .then_some(FieldPropertyDescriptor {
                enumerable: self.mode != "nonenumerable" || name != "accessTokenExpiresAt",
            }))
    }

    fn get(&self, name: &str) -> AuthResult<Option<FieldValue>> {
        Ok(self.fields.lock().unwrap().get(name).cloned())
    }

    fn get_with_receiver(
        &self,
        name: &str,
        receiver: &FieldValue,
    ) -> AuthResult<Option<FieldValue>> {
        assert!(receiver.strict_equals(self.receiver.lock().unwrap().as_ref().unwrap()));
        assert_eq!(name, "accessTokenExpiresAt");
        self.events.lock().unwrap().push("get");
        if self.mode == "get-throws" {
            return Err(AuthError::from_thrown(self.original.clone()));
        }
        self.get(name)
    }

    fn set(&self, name: String, value: FieldValue) -> AuthResult<Option<FieldValue>> {
        Ok(self.fields.lock().unwrap().insert(name, value))
    }

    fn set_with_receiver(
        &self,
        name: String,
        value: FieldValue,
        receiver: &FieldValue,
    ) -> AuthResult<()> {
        assert!(receiver.strict_equals(self.receiver.lock().unwrap().as_ref().unwrap()));
        assert_eq!(name, "accessTokenExpiresAt");
        self.events.lock().unwrap().push("set");
        match self.mode {
            "set-throws" => Err(AuthError::from_thrown(self.original.clone())),
            "readonly" => Err(AuthError::type_error(
                "Attempted to assign to readonly property.",
            )),
            _ => self.set(name, value).map(drop),
        }
    }

    fn delete(&self, _: &str) -> AuthResult<Option<FieldValue>> {
        Err(AuthError::internal(
            "Expiry defaults must not delete a property",
        ))
    }

    fn snapshot_fields(&self) -> AuthResult<FieldMap> {
        Err(AuthError::internal(
            "Expiry defaults must not snapshot token properties",
        ))
    }

    fn identity(&self) -> usize {
        std::ptr::from_ref(self).addr()
    }
}

#[tokio::test]
async fn expiry_defaults_preserve_accessors_errors_and_mutation_identity() -> AuthResult<()> {
    for mode in [
        "truthy",
        "falsy",
        "get-throws",
        "set-throws",
        "readonly",
        "nonenumerable",
    ] {
        let original: FieldValue = FieldMap::from([(
            "message".into(),
            "Native token callback original failure".into(),
        )])
        .into();
        let initial = if mode == "truthy" {
            value("date")
        } else {
            FieldValue::Undefined
        };
        let source = Arc::new(ExpirySource {
            mode,
            fields: Mutex::new(FieldMap::from([(
                "accessTokenExpiresAt".into(),
                initial.clone(),
            )])),
            receiver: Mutex::new(None),
            events: Mutex::new(Vec::new()),
            original: original.clone(),
        });
        let token: FieldValue = FieldObject::from_source(source.clone()).into();
        *source.receiver.lock().unwrap() = Some(token.clone());
        let request = input(None);
        let exchange = Arc::new(Exchange {
            input: request.clone(),
            result: token.clone(),
            error: None,
            calls: Mutex::new(0),
        });
        let result = validate_authorization_code_native_via_provider(
            &provider(exchange, Some(30.0)),
            &request,
        )
        .await;
        assert_eq!(
            *source.events.lock().unwrap(),
            if matches!(mode, "truthy" | "get-throws") {
                vec!["get"]
            } else {
                vec!["get", "set"]
            }
        );
        match mode {
            "get-throws" | "set-throws" => assert!(
                result
                    .unwrap_err()
                    .raw_value()
                    .unwrap()
                    .strict_equals(&original)
            ),
            "readonly" => assert!(
                matches!(result, Err(AuthError::TypeError(message)) if message == "Attempted to assign to readonly property.")
            ),
            _ => assert!(result?.strict_equals(&token)),
        }
        let stored = source.get("accessTokenExpiresAt")?.unwrap();
        if matches!(mode, "get-throws" | "set-throws" | "readonly") {
            assert!(stored.is_undefined());
        } else if mode == "truthy" {
            assert!(stored.strict_equals(&initial));
        } else {
            assert!(stored.as_date().is_some());
        }
        if mode == "nonenumerable" {
            assert!(
                !source
                    .own_property_descriptor("accessTokenExpiresAt")?
                    .unwrap()
                    .enumerable
            );
        }
        *source.receiver.lock().unwrap() = None;
    }
    let request = input(None);
    let original = value("object");
    let exchange = Arc::new(Exchange {
        input: request.clone(),
        result: value("object"),
        error: Some(original.clone()),
        calls: Mutex::new(0),
    });
    let error =
        validate_authorization_code_native_via_provider(&provider(exchange, Some(30.0)), &request)
            .await
            .unwrap_err();
    assert!(error.raw_value().unwrap().strict_equals(&original));
    Ok(())
}

#[tokio::test]
async fn expiry_assignment_keeps_sparse_array_indices_and_native_children() -> AuthResult<()> {
    let token: FieldValue = FieldArray::with_length(3).into();
    let child = value("object");
    token.set_model_property("0", child.clone())?;
    token.set_model_property("2", "last".into())?;
    let request = input(None);
    let exchange = Arc::new(Exchange {
        input: request.clone(),
        result: token.clone(),
        error: None,
        calls: Mutex::new(0),
    });
    let result =
        validate_authorization_code_native_via_provider(&provider(exchange, Some(30.0)), &request)
            .await?;
    assert!(result.strict_equals(&token));
    assert_eq!(result.as_array().unwrap().own_indices()?, [0, 2]);
    assert!(result.model_property("0")?.strict_equals(&child));
    assert!(
        result
            .model_property("accessTokenExpiresAt")?
            .as_date()
            .is_some()
    );
    assert_eq!(
        result
            .enumerable_fields()?
            .keys()
            .map(String::as_str)
            .collect::<Vec<_>>(),
        ["0", "2", "accessTokenExpiresAt"]
    );
    Ok(())
}
