//! Paired with social-http-envelope.test.mjs using real HTTP bodies and native observations.

use super::*;
use better_auth_core::{
    AuthConfig, AuthContext, FieldMap, FieldValue, Utf16String,
    observability::{LogArgument, LogLevel, LogSink, LoggerConfig},
    request_runtime::NativeRequest,
    store::{EphemeralStore, StatelessSchema},
};

#[derive(Default)]
struct Logs(Mutex<Vec<(LogLevel, String, Vec<FieldValue>)>>);

impl LogSink for Logs {
    fn log(&self, level: LogLevel, message: LogArgument<'_>, arguments: &[LogArgument<'_>]) {
        self.0.lock().unwrap().push((
            level,
            message.to_string(),
            arguments
                .iter()
                .map(|argument| match argument {
                    LogArgument::Native(value) => (*value).clone(),
                    LogArgument::Value(value) => (*value).clone().into(),
                    LogArgument::Text(value) => (*value).into(),
                    LogArgument::Error(error) => error.to_string().into(),
                })
                .collect(),
        ));
    }
}

struct Probe {
    inputs: Mutex<Vec<FieldValue>>,
    failure: Option<FieldValue>,
    events: Arc<Mutex<Vec<&'static str>>>,
}

#[async_trait]
impl OAuthProfileMapper for Probe {
    async fn map_profile_native(&self, profile: &FieldValue) -> AuthResult<FieldValue> {
        self.events.lock().unwrap().push("mapper");
        self.inputs.lock().unwrap().push(profile.clone());
        if let Some(failure) = &self.failure {
            return Err(AuthError::from_thrown(failure.clone()));
        }
        Ok(FieldMap::from([
            ("marker".into(), "mapped".into()),
            ("optional".into(), FieldValue::Undefined),
        ])
        .into())
    }
}

struct Run {
    result: AuthResult<social_profile::ProviderProfile>,
    probe: Arc<Probe>,
    logs: Arc<Logs>,
}

async fn run(
    id: &str,
    body: &str,
    status: &'static str,
    content_type: &'static str,
    failure: Option<FieldValue>,
) -> Run {
    let probe = Arc::new(Probe {
        inputs: Mutex::default(),
        failure,
        events: Arc::default(),
    });
    let case = &fixture()["providers"][id];
    let server = ProfileServer::with_body(
        body.into(),
        probe.events.clone(),
        case["profileMethod"].as_str().unwrap_or("GET"),
        case.get("profileBody").cloned(),
        status,
        content_type,
    )
    .await;
    let mut config = provider(id);
    config.user_info_url = Some(format!("{}/profile", server.url));
    config.map_profile_to_user = Some(probe.clone());
    let resolved = resolve(id, config).await;
    let logs = Arc::new(Logs::default());
    let mut config = AuthConfig::new("http-envelope-contract-secret-at-least-32-characters")
        .base_url("http://http-envelope.test");
    config.logger = LoggerConfig {
        log: Some(logs.clone()),
        ..Default::default()
    };
    let config = Arc::new(config);
    let context =
        AuthContext::<StatelessSchema>::new(config.clone(), Arc::new(EphemeralStore::new(config)));
    let request = OAuthUserInfoRequest {
        access_token: Some("ordinary-access".into()).into(),
        ..Default::default()
    };
    let tokens = OAuthTokenSet::from_fields(request.fields());
    let result = context
        .with_native_context(NativeRequest::default(), |_| async {
            social_profile::fetch_user_info_for_code(
                &resolved.providers[id],
                &tokens,
                request,
                None,
            )
            .await
        })
        .await;
    Run {
        result,
        probe,
        logs,
    }
}

fn mapped(mut fields: FieldMap) -> FieldValue {
    fields.extend([
        ("marker".into(), "mapped".into()),
        ("optional".into(), FieldValue::Undefined),
    ]);
    fields.into()
}

fn assert_response(response: &social_profile::ProviderProfile, user: FieldValue, data: FieldValue) {
    assert_eq!(
        response.value,
        FieldValue::from(FieldMap::from([
            ("user".into(), user.clone()),
            ("data".into(), data),
        ]))
    );
    assert_eq!(
        response.value.as_object().unwrap().own_keys().unwrap(),
        ["user", "data"]
    );
    assert_eq!(
        profile_test_support::property(response, "user")
            .as_object()
            .unwrap()
            .own_keys()
            .unwrap(),
        user.as_object().unwrap().own_keys().unwrap()
    );
}

#[tokio::test]
async fn wrapper_false_values_skip_mapper_and_preserve_cloudflare_undefined_diagnostic() {
    for value in [json!(false), json!(0), json!(""), Value::Null] {
        for id in ["cloudflare", "linear", "notion"] {
            let body = match id {
                "cloudflare" => json!({"success": true, "result": value}),
                "linear" => json!({"data": {"viewer": value}}),
                _ => json!({"bot": {"owner": {"user": value}}}),
            };
            let run = run(id, &body.to_string(), "200 OK", "application/json", None).await;
            assert!(run.result.unwrap().value.is_null(), "{id}: {value}");
            assert!(run.probe.inputs.lock().unwrap().is_empty());
            assert_eq!(*run.probe.events.lock().unwrap(), ["http"]);
            assert_eq!(
                *run.logs.0.lock().unwrap(),
                if id == "cloudflare" {
                    vec![(
                        LogLevel::Error,
                        "Failed to fetch user info from Cloudflare:".into(),
                        vec![FieldValue::Undefined],
                    )]
                } else {
                    Vec::new()
                }
            );
        }
    }
}

#[tokio::test]
async fn cloudflare_truthy_success_keeps_full_native_result_and_mapper_fields() {
    let profile = fixture()["providers"]["cloudflare"]["profile"].clone();
    for success in [json!("accepted"), json!([]), json!({})] {
        let run = run(
            "cloudflare",
            &json!({"success":success,"result":profile}).to_string(),
            "200 OK",
            "application/json",
            None,
        )
        .await;
        let response = run.result.unwrap();
        assert_response(
            &response,
            mapped(FieldMap::from([
                ("name".into(), "Cloudflare Owner".into()),
                ("email".into(), profile["email"].clone().into()),
                ("emailVerified".into(), false.into()),
            ])),
            profile.clone().into(),
        );
        let inputs = run.probe.inputs.lock().unwrap();
        assert_eq!(inputs.as_slice(), &[FieldValue::from(profile.clone())]);
        assert!(profile_test_support::property(&response, "data").strict_equals(&inputs[0]));
        assert_eq!(*run.probe.events.lock().unwrap(), ["http", "mapper"]);
        assert!(run.logs.0.lock().unwrap().is_empty());
    }
}

#[tokio::test]
async fn kick_mapper_undefined_preserves_thrown_identity_before_native_property_read() {
    let failure: FieldValue = FieldMap::from([
        ("name".into(), "MapperFailure".into()),
        ("message".into(), "original mapper failure".into()),
        ("optional".into(), FieldValue::Undefined),
    ])
    .into();
    let run = run(
        "kick",
        r#"{"data":[]}"#,
        "200 OK",
        "application/json",
        Some(failure.clone()),
    )
    .await;
    assert!(
        run.result
            .unwrap_err()
            .raw_value()
            .unwrap()
            .strict_equals(&failure)
    );
    assert_eq!(*run.probe.inputs.lock().unwrap(), [FieldValue::Undefined]);
    assert_eq!(*run.probe.events.lock().unwrap(), ["http", "mapper"]);
    assert!(run.logs.0.lock().unwrap().is_empty());
}

#[tokio::test]
async fn kick_undefined_native_read_retains_complete_rust_error_observation() {
    let run = run("kick", r#"{"data":[]}"#, "200 OK", "application/json", None).await;
    let error = run.result.unwrap_err();
    assert!(
        matches!(&error, AuthError::TypeError(message) if message == "Cannot read properties of undefined (reading 'name')")
    );
    eprintln!(
        "{}",
        json!({"case":"kick-undefined-read", "runtime":"rust", "error":{"name":"TypeError", "message":error.message_value().unwrap().json().unwrap()}})
    );
    assert_eq!(*run.probe.inputs.lock().unwrap(), [FieldValue::Undefined]);
    assert_eq!(*run.probe.events.lock().unwrap(), ["http", "mapper"]);
    assert!(run.logs.0.lock().unwrap().is_empty());
}

#[tokio::test]
async fn malformed_json_and_empty_text_reach_mapper_without_date_revival_or_parse_error() {
    for (body, content_type) in [
        ("{not-json", "application/json"),
        ("", "application/json"),
        ("plain profile", "text/plain"),
    ] {
        let run = run("huggingface", body, "200 OK", content_type, None).await;
        assert_response(
            &run.result.unwrap(),
            mapped(FieldMap::from([
                ("name".into(), "".into()),
                ("email".into(), FieldValue::Undefined),
                ("image".into(), FieldValue::Undefined),
                ("emailVerified".into(), false.into()),
            ])),
            body.into(),
        );
        assert_eq!(*run.probe.inputs.lock().unwrap(), [FieldValue::from(body)]);
        assert_eq!(*run.probe.events.lock().unwrap(), ["http", "mapper"]);
        assert!(run.logs.0.lock().unwrap().is_empty());
    }
}

#[tokio::test]
async fn native_http_parser_preserves_utf16_values_and_date_strings() {
    let body = r#"{"sub":"utf16-owner","name":"\ud800","email":"owner@example.test","picture":null,"email_verified":true,"seenAt":"2025-01-01T00:00:00.000Z"}"#;
    let run = run("huggingface", body, "200 OK", "application/json", None).await;
    let response = run.result.unwrap();
    let expected = FieldValue::parse_json(body).unwrap();
    assert_response(
        &response,
        mapped(FieldMap::from([
            ("name".into(), Utf16String::from_units(vec![0xd800]).into()),
            ("email".into(), "owner@example.test".into()),
            ("image".into(), FieldValue::Null),
            ("emailVerified".into(), true.into()),
        ])),
        expected.clone(),
    );
    let inputs = run.probe.inputs.lock().unwrap();
    assert_eq!(inputs.as_slice(), &[expected]);
    assert!(profile_test_support::property(&response, "data").strict_equals(&inputs[0]));
    assert_eq!(*run.probe.events.lock().unwrap(), ["http", "mapper"]);
    assert!(run.logs.0.lock().unwrap().is_empty());
}

#[tokio::test]
async fn cloudflare_http_error_retains_complete_native_spread_and_original_status_text() {
    let body = r#"{"status":1,"statusText":"overwritten","detail":"\ud800","extra":null}"#;
    let run = run(
        "cloudflare",
        body,
        "503 Provider Unavailable",
        "application/json",
        None,
    )
    .await;
    assert!(run.result.unwrap().value.is_null());
    assert!(run.probe.inputs.lock().unwrap().is_empty());
    assert_eq!(*run.probe.events.lock().unwrap(), ["http"]);
    let expected: FieldValue = FieldMap::from([
        ("status".into(), 503.0.into()),
        ("statusText".into(), "Provider Unavailable".into()),
        (
            "detail".into(),
            Utf16String::from_units(vec![0xd800]).into(),
        ),
        ("extra".into(), FieldValue::Null),
    ])
    .into();
    let logs = run.logs.0.lock().unwrap();
    assert_eq!(
        *logs,
        [(
            LogLevel::Error,
            "Failed to fetch user info from Cloudflare:".into(),
            vec![expected]
        )]
    );
    assert_eq!(
        logs[0].2[0].as_object().unwrap().own_keys().unwrap(),
        ["status", "statusText", "detail", "extra"]
    );
}
