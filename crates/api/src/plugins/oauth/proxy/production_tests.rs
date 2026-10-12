//! Exercise the production callback through native token consumption and encrypted redirect output.

#![expect(
    clippy::unwrap_used,
    clippy::panic_in_result_fn,
    reason = "Regression assertions inspect native identities, complete payloads, and unchanged storage."
)]

use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use better_auth_core::{
    AuthConfig, AuthContext, AuthError, AuthPlugin, AuthRequest, AuthResult, FieldArray, FieldDate,
    FieldFunction, FieldMap, FieldValue, Headers, HttpMethod,
    endpoint_input::ValidatedInput,
    store::{EphemeralStore, StatelessSchema, schema::EntityRole},
};
use serde_json::{Value, json};

use super::super::{
    GenericOAuthConfig, GenericOAuthProfileContext, GenericOAuthUserInfoHandler,
    OAuthAccountSubject, OAuthPlugin, OAuthTokenHandler, OAuthUserInfoRequest,
};
use super::OAuthProxyPlugin;
use crate::plugins::{symmetric, test_helpers};

const ORIGIN: &str = "https://oauth-proxy-callback.test";
const SECRET: &str = "oauth-proxy-callback-contract-secret-at-least-thirty-two-characters";

struct Provider {
    token: FieldValue,
    profile: FieldValue,
    events: Mutex<Vec<&'static str>>,
    failure: Option<FieldValue>,
}

#[async_trait]
impl OAuthTokenHandler for Provider {
    async fn get_token_native(&self, input: &FieldValue) -> AuthResult<FieldValue> {
        self.events.lock().unwrap().push("token");
        assert_eq!(
            input.as_object().unwrap().own_keys()?,
            ["code", "codeVerifier", "redirectURI"]
        );
        assert_eq!(input.model_property("code")?, "callback-code".into());
        assert_eq!(
            input
                .model_property("codeVerifier")?
                .as_date()
                .unwrap()
                .milliseconds(),
            1_893_553_445_000.0
        );
        assert!(!input.has_property("deviceId")?);
        assert_eq!(
            input.model_property("redirectURI")?,
            format!("{ORIGIN}/api/auth/callback/fixture").into()
        );
        Ok(self.token.clone())
    }
}

#[async_trait]
impl GenericOAuthUserInfoHandler for Provider {
    async fn get_user_info_native(
        &self,
        input: &OAuthUserInfoRequest,
        _: GenericOAuthProfileContext<'_>,
    ) -> AuthResult<FieldValue> {
        self.events.lock().unwrap().push("userinfo");
        let fields = input.fields();
        assert_eq!(
            fields.get("accessToken"),
            Some(&FieldValue::from("before-userinfo"))
        );
        assert_eq!(
            fields.get("user").unwrap().json()?,
            Some(json!({"providerName": "parsed user"}))
        );
        assert!(
            fields
                .get("extra")
                .unwrap()
                .strict_equals(&self.token.model_property("extra")?)
        );
        self.token.set_model_property(
            "accessToken",
            FieldMap::from([("marker".into(), "after-userinfo".into())]).into(),
        )?;
        Ok(self.profile.clone())
    }
}

#[async_trait]
impl OAuthAccountSubject for Provider {
    async fn resolve_subject_native(
        &self,
        token: &FieldValue,
        profile: &FieldValue,
    ) -> AuthResult<FieldValue> {
        self.events.lock().unwrap().push("subject");
        assert!(token.strict_equals(&self.token));
        assert!(profile.strict_equals(&self.profile));
        assert_eq!(
            token
                .model_property("accessToken")?
                .model_property("marker")?,
            "after-userinfo".into()
        );
        if let Some(failure) = &self.failure {
            return Err(AuthError::from_thrown(failure.clone()));
        }
        token.set_model_property(
            "refreshToken",
            FieldMap::from([("subject".into(), true.into())]).into(),
        )?;
        Ok("stable-subject".into())
    }
}

fn provider(kind: &str, failure: Option<FieldValue>) -> Arc<Provider> {
    let extra: FieldValue = FieldMap::from([
        ("ownUndefined".into(), FieldValue::Undefined),
        ("invalid".into(), FieldDate::invalid().into()),
        ("nan".into(), f64::NAN.into()),
    ])
    .into();
    let properties = FieldMap::from([
        ("accessToken".into(), "before-userinfo".into()),
        ("refreshToken".into(), FieldValue::Undefined),
        ("accessTokenExpiresAt".into(), FieldDate::invalid().into()),
        (
            "scopes".into(),
            vec![
                "profile".into(),
                FieldValue::Null,
                FieldValue::Undefined,
                3.into(),
            ]
            .into(),
        ),
        ("extra".into(), extra.clone()),
    ]);
    let token = match kind {
        "array" => FieldArray::with_length_and_properties(3, properties.into()).into(),
        "date" => FieldDate::from_milliseconds_with_properties(0.0, properties.into()).into(),
        "function" => FieldFunction::contextual_with_properties(
            |_, _| Ok(FieldValue::Undefined),
            properties.into(),
        )
        .into(),
        _ => properties.into(),
    };
    Arc::new(Provider {
        token,
        profile: FieldMap::from([
            ("id".into(), "source-subject".into()),
            ("email".into(), "native@provider.test".into()),
            ("name".into(), 0.into()),
            ("emailVerified".into(), false.into()),
            ("image".into(), FieldValue::Null),
            ("extra".into(), extra),
        ])
        .into(),
        events: Mutex::new(Vec::new()),
        failure,
    })
}

async fn context(
    provider: Arc<Provider>,
    disable_sign_up: Option<bool>,
) -> AuthResult<(AuthContext<StatelessSchema>, Arc<EphemeralStore>)> {
    let oauth = OAuthPlugin::new().add_generic_provider(
        "fixture",
        GenericOAuthConfig {
            client_id: "client".into(),
            client_secret: Some("secret".into()),
            authorization_url: Some(format!("{ORIGIN}/authorize")),
            get_token: Some(provider.clone()),
            get_user_info: Some(provider.clone()),
            account_subject: Some(provider),
            disable_sign_up,
            ..Default::default()
        },
    );
    let config = Arc::new(AuthConfig::new(SECRET).base_url(ORIGIN));
    let store = Arc::new(EphemeralStore::new(config.clone()));
    let context = test_helpers::initialize_test_context(config, store.clone(), &[&oauth]).await?;
    Ok((context, store))
}

fn request() -> AuthResult<AuthRequest> {
    let fixture: Value = serde_json::from_str(include_str!(
        "../../../../../../tests/fixtures/oauth-proxy-callback-1.7.6.json"
    ))?;
    let record = fixture
        .get("cases")
        .unwrap()
        .as_array()
        .unwrap()
        .iter()
        .find(|case| {
            case.get("name").and_then(Value::as_str) == Some("parseJSON-revives-code-verifier-date")
        })
        .unwrap();
    let ciphertext = record
        .get("encryption")
        .unwrap()
        .get("ciphertext")
        .unwrap()
        .as_str()
        .unwrap();
    let mut request = AuthRequest::new(HttpMethod::Get, "/callback/fixture");
    request.set_endpoint_query(ValidatedInput::unvalidated_native(
        FieldMap::from([
            ("state".into(), ciphertext.into()),
            ("code".into(), FieldValue::Null),
        ])
        .into(),
    ));
    request.set_endpoint_body(ValidatedInput::unvalidated_native(
        FieldMap::from([
            ("state".into(), "body-state-must-not-win".into()),
            ("code".into(), "callback-code".into()),
            ("user".into(), "{\"providerName\":\"parsed user\"}".into()),
        ])
        .into(),
    ));
    Ok(request)
}

fn unchanged(store: &EphemeralStore) -> AuthResult<()> {
    for role in [
        EntityRole::User,
        EntityRole::Session,
        EntityRole::Account,
        EntityRole::Verification,
    ] {
        assert!(store.storage_rows(role)?.is_empty(), "{role:?}");
    }
    Ok(())
}

#[tokio::test]
async fn original_ciphertext_flows_through_native_tokens_to_complete_encrypted_payload()
-> AuthResult<()> {
    for kind in ["object", "array", "date", "function"] {
        for disable_sign_up in [None, Some(false)] {
            let provider = provider(kind, None);
            let (context, store) = context(provider.clone(), disable_sign_up).await?;
            let request = request()?;
            request.set_response_header("x-kept", "original")?;
            let headers = request.response_headers_value()?;
            let before = chrono::Utc::now().timestamp_millis();
            let error = OAuthProxyPlugin::new()
                .before_request(&request, &context)
                .await
                .unwrap_err();
            let after = chrono::Utc::now().timestamp_millis();
            assert!(error.is_found_redirect()?);
            assert!(error.headers_value()?.strict_equals(&headers));
            let headers = Headers::from_field_value(&headers)?;
            assert_eq!(headers.get("x-kept").map(String::as_str), Some("original"));
            let redirect = url::Url::parse(headers.get("location").unwrap()).unwrap();
            assert_eq!(redirect.origin().ascii_serialization(), ORIGIN);
            assert_eq!(redirect.path(), "/complete");
            let pairs = redirect.query_pairs().collect::<Vec<_>>();
            assert_eq!(pairs.len(), 1);
            let (key, encrypted) = pairs.first().unwrap();
            assert_eq!(key, "profile");
            let plain = symmetric::decrypt(SECRET, encrypted)?;
            let mut payload: Value = serde_json::from_str(&plain)?;
            let mut expected_keys = vec![
                "userInfo",
                "profile",
                "scopes",
                "account",
                "state",
                "callbackURL",
                "errorURL",
            ];
            if disable_sign_up.is_some() {
                expected_keys.push("disableSignUp");
            }
            expected_keys.push("timestamp");
            assert_eq!(
                payload
                    .as_object()
                    .unwrap()
                    .keys()
                    .map(String::as_str)
                    .collect::<Vec<_>>(),
                expected_keys
            );
            let timestamp = payload
                .as_object_mut()
                .unwrap()
                .remove("timestamp")
                .unwrap()
                .as_i64()
                .unwrap();
            assert!(timestamp >= before && timestamp <= after);
            let mut expected = json!({
                "userInfo": {"id": "stable-subject", "email": "native@provider.test", "name": "", "emailVerified": false},
                "profile": {"id": "source-subject", "email": "native@provider.test", "name": 0, "emailVerified": false, "image": null, "extra": {"invalid": null, "nan": null}},
                "scopes": ["profile", null, null, 3],
                "account": {"providerId": "fixture", "accountId": "stable-subject", "accessToken": {"marker": "after-userinfo"}, "refreshToken": {"subject": true}, "accessTokenExpiresAt": null, "scope": "profile,,,3"},
                "state": "original-proxy-state",
                "callbackURL": "https://oauth-proxy-callback.test/complete",
                "errorURL": "https://oauth-proxy-callback.test/failure?kept=1"
            });
            if let Some(disable_sign_up) = disable_sign_up {
                let _ = expected
                    .as_object_mut()
                    .unwrap()
                    .insert("disableSignUp".into(), disable_sign_up.into());
            }
            assert_eq!(payload, expected, "{kind}/{disable_sign_up:?}");
            assert_eq!(
                *provider.events.lock().unwrap(),
                ["token", "userinfo", "subject"]
            );
            assert_eq!(
                provider.token.model_property("refreshToken")?.json()?,
                Some(json!({"subject": true}))
            );
            unchanged(&store)?;
        }
    }
    Ok(())
}

#[tokio::test]
async fn subject_failure_redirects_after_userinfo_without_rolling_back_token_mutation()
-> AuthResult<()> {
    let failure: FieldValue =
        FieldMap::from([("detail".into(), FieldDate::invalid().into())]).into();
    let provider = provider("object", Some(failure));
    let (context, store) = context(provider.clone(), None).await?;
    let request = request()?;
    let error = OAuthProxyPlugin::new()
        .before_request(&request, &context)
        .await
        .unwrap_err();
    assert!(error.is_found_redirect()?);
    assert_eq!(
        Headers::from_field_value(&error.headers_value()?)?
            .get("location")
            .map(String::as_str),
        Some("https://oauth-proxy-callback.test/failure?kept=1&error=unable_to_get_user_info")
    );
    assert_eq!(
        *provider.events.lock().unwrap(),
        ["token", "userinfo", "subject"]
    );
    assert_eq!(
        provider.token.model_property("accessToken")?.json()?,
        Some(json!({"marker": "after-userinfo"}))
    );
    assert!(
        provider
            .token
            .model_property("refreshToken")?
            .is_undefined()
    );
    unchanged(&store)
}
