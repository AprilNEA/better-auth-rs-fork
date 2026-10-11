//! Account-info preserves native token values until the provider consumes the token record.

use super::*;
use better_auth_api::plugins::oauth::{
    OAuthUserInfoHandler, OAuthUserInfoRequest, OAuthUserInfoResponse,
};
use better_auth_core::{
    AuthResult, FieldMap, FieldValue,
    user_fields::{FieldTransforms, UserFieldConfig, UserFieldTransform},
};

struct NativeProfile {
    access_token: FieldValue,
    id_token: FieldValue,
    calls: Arc<std::sync::Mutex<Vec<FieldMap>>>,
}

#[async_trait]
impl OAuthUserInfoHandler for NativeProfile {
    async fn get_user_info(
        &self,
        request: OAuthUserInfoRequest,
    ) -> AuthResult<Option<OAuthUserInfoResponse>> {
        let fields = request.fields();
        assert_eq!(
            fields.keys().map(String::as_str).collect::<Vec<_>>(),
            ["accessToken", "accessTokenExpiresAt", "scopes", "idToken"]
        );
        assert!(fields["accessToken"].strict_equals(&self.access_token));
        assert!(fields["idToken"].strict_equals(&self.id_token));
        assert_eq!(
            fields["accessTokenExpiresAt"],
            FieldValue::Number(4_102_444_800_000.0)
        );
        assert_eq!(fields["scopes"].json()?, Some(json!(["email profile"])));
        let _ = fields["idToken"]
            .as_object()
            .unwrap()
            .set("observed", true.into())?;
        self.calls.lock().unwrap().push(fields);
        Ok(Some(OAuthUserInfoResponse {
            user: OAuthUserInfo {
                id: "provider-owner".into(),
                name: Some("Provider Owner".into()).into(),
                email: Some("native-tokens@example.com".into()).into(),
                email_verified: Some(true).into(),
                image: None,
                additional_fields: Default::default(),
            },
            data: json!({"sub": "provider-owner"}),
        }))
    }
}

#[tokio::test]
async fn test_account_info_preserves_number_expiry_and_native_token_identity() {
    for access_token in [
        FieldValue::Number(7.0),
        FieldMap::from([("credential".into(), "native-access".into())]).into(),
    ] {
        let mut config = test_config();
        let db = create_test_database().await;
        let (user_id, session_token, account_id) = setup_user_with_account(
            &db,
            &Arc::new(config.clone()),
            "native-tokens@example.com",
            "google",
            Some("stored-access".into()),
            Some("stored-refresh".into()),
        )
        .await;
        let before = db.get_user_accounts(&user_id).await.unwrap().remove(0);
        let before = before.internal_fields().unwrap().json().unwrap();
        let id_token: FieldValue = FieldMap::from([
            (
                "claims".into(),
                FieldMap::from([("sub".into(), "native-id".into())]).into(),
            ),
            ("absent".into(), FieldValue::Undefined),
        ])
        .into();
        for (name, value) in [
            ("accessToken", access_token.clone()),
            ("idToken", id_token.clone()),
            (
                "accessTokenExpiresAt",
                FieldValue::Number(4_102_444_800_000.0),
            ),
        ] {
            let _ = config.account.additional_fields.insert(
                name.into(),
                UserFieldConfig {
                    transform: Some(FieldTransforms {
                        output: Some(UserFieldTransform::new(move |_| Ok(value.clone()))),
                        ..Default::default()
                    }),
                    ..Default::default()
                },
            );
        }
        let calls = Arc::new(std::sync::Mutex::new(Vec::new()));
        let mut provider = make_test_provider("http://localhost:65535");
        provider.get_user_info = Some(Arc::new(NativeProfile {
            access_token: access_token.clone(),
            id_token: id_token.clone(),
            calls: calls.clone(),
        }));
        let mut oauth_config = OAuthConfig::default();
        let _ = oauth_config.providers.insert("google".into(), provider);
        let plugin = OAuthPlugin::with_config(oauth_config);
        let config = Arc::new(config);
        let runtime = db
            .with_runtime(config.clone(), Vec::new(), Default::default())
            .unwrap();
        let context = AuthContext::new(config, runtime)
            .initialize_request_context()
            .await
            .unwrap();
        let mut request = AuthRequest::new(HttpMethod::Get, "/account-info");
        request.query = Some(json!({"accountId": account_id}));
        let _ = request
            .headers
            .insert("cookie".into(), session_cookie(&session_token));
        let response = refresh_cookie::dispatch(&plugin, &request, &context)
            .await
            .unwrap();
        assert_eq!(response.status, 200);
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&response.body.bytes().unwrap()).unwrap(),
            json!({
                "user": {
                    "id": "provider-owner", "name": "Provider Owner",
                    "email": "native-tokens@example.com", "emailVerified": true
                },
                "data": {"sub": "provider-owner"},
                "account": {"id": account_id, "providerId": "google", "accountId": "google-account-id"}
            })
        );
        assert_eq!(response.headers.get_all("Set-Cookie").count(), 0);
        {
            let calls = calls.lock().unwrap();
            assert_eq!(calls.len(), 1);
            assert_eq!(
                calls[0].json().unwrap(),
                json!({
                    "accessToken": access_token.json().unwrap(),
                    "accessTokenExpiresAt": 4_102_444_800_000.0,
                    "scopes": ["email profile"],
                    "idToken": {"claims": {"sub": "native-id"}, "observed": true}
                })
                .as_object()
                .unwrap()
                .clone()
            );
        }
        assert!(
            id_token
                .model_property("observed")
                .unwrap()
                .strict_equals(&true.into())
        );
        let after = db.get_user_accounts(&user_id).await.unwrap().remove(0);
        assert_eq!(after.internal_fields().unwrap().json().unwrap(), before);
    }
}
