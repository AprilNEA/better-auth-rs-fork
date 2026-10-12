#![expect(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::panic_in_result_fn,
    reason = "Pinned Auth contracts must fail immediately on invalid source fixtures or business observations."
)]

use super::*;
use crate::plugins::{
    OAuthProxyConfig, OAuthProxyPlugin,
    password_management::PasswordManagementPlugin,
    test_helpers::verification_consumer_native::{
        Harness, NOW, ORIGIN, ReplayFailures, SECRET, assert_replay, consumer_user, date,
    },
};
use better_auth_core::{AuthPlugin, Headers, HttpMethod, store::StatelessSchema};
use serde_json::{Value as Json, json};

mod trust;

fn headers(headers: &Headers) -> Json {
    let mut pairs = headers
        .iter()
        .map(|(name, value)| (name.to_ascii_lowercase(), value.clone()))
        .collect::<Vec<_>>();
    pairs.sort_by(|left, right| left.0.cmp(&right.0));
    json!(pairs)
}

fn cookies(headers: &Headers) -> Json {
    json!(headers.get_all("set-cookie").collect::<Vec<_>>())
}

fn request_cookie(
    request: &mut AuthRequest,
    context: &AuthContext<StatelessSchema>,
    suffix: &str,
    value: &str,
) -> AuthResult<()> {
    let name = related_cookie_name(&context.config, suffix);
    let signed = sign_cookie_value(SECRET, value)?;
    let _ = request
        .headers
        .insert("cookie".to_owned(), format!("{name}={signed}"));
    Ok(())
}

async fn password(scenario: &Json) -> AuthResult<Json> {
    let harness = Harness::new(scenario, "reset-password:native-token")?;
    let plugin = PasswordManagementPlugin::new();
    let (context, inner) = harness.context(&[&plugin]).await?;
    let mut request = AuthRequest::new(HttpMethod::Get, "/reset-password/native-token");
    request.query = Some(json!({"callbackURL":format!("{ORIGIN}/reset?kept=1")}));
    let before = harness.state(&inner)?;
    harness.activate();
    let harness = &harness;
    let request_ref = &request;
    let result = context
        .with_http_context(&request, |context| async move {
            let response = match plugin.on_request(request_ref, &context).await {
                Ok(response) => response.unwrap().into_http_response()?,
                Err(error) => {
                    better_auth_core::api_error::handle_http_error(error, &context).await?
                }
            };
            FieldValue::from_json(json!({
                "status":response.status,
                "headers":headers(&response.headers),
                "cookies":cookies(&response.headers),
                "body":String::from_utf8(response.body.into_bytes()?).unwrap(),
            }))
        })
        .await;
    harness.finish(before, harness.outcome(result)?, &inner)
}

fn resolved(state: &ResolvedTwoFactorState) -> FieldValue {
    let session = match state {
        ResolvedTwoFactorState::Session { data, .. } => FieldMap::from(data.session.clone()).into(),
        ResolvedTwoFactorState::Pending(_) => FieldValue::Null,
    };
    FieldMap::from([
        (
            "session".into(),
            FieldMap::from([("session".into(), session), ("user".into(), state.user())]).into(),
        ),
        ("key".into(), state.key().into()),
    ])
    .into()
}

async fn two_factor(scenario: &Json) -> AuthResult<Json> {
    let identifier = "2fa-native";
    let harness = Harness::new(scenario, identifier)?;
    let rearm = scenario["consumer"] == "two-factor-rearm";
    if rearm {
        let attempts = FieldValue::from(FieldMap::from([
            ("id".into(), "attempts-row".into()),
            (
                "identifier".into(),
                format!("2fa-attempts-{identifier}").into(),
            ),
            (
                "value".into(),
                if scenario["exhausted"] == true {
                    "3"
                } else {
                    "0"
                }
                .into(),
            ),
            ("expiresAt".into(), date((NOW + 60_000) as f64)),
            ("createdAt".into(), date(NOW as f64)),
            ("updatedAt".into(), date(NOW as f64)),
        ]));
        harness.cache.insert(
            &format!("verification:2fa-attempts-{identifier}"),
            attempts.stringify()?.unwrap().into(),
        )?;
    }
    let plugin = TwoFactorPlugin::new();
    let (context, inner) = harness.context(&[&plugin]).await?;
    let mut request = AuthRequest::new(HttpMethod::Post, "/native-verification-consumer");
    request_cookie(&mut request, &context, TWO_FACTOR_COOKIE_SUFFIX, identifier)?;
    let before = harness.state(&inner)?;
    harness.activate();
    let harness = &harness;
    let result = context
        .with_native_context(
            better_auth_core::NativeRequest::default(),
            |context| async move {
                let result: AuthResult<FieldValue> = async {
                    let state = resolve_two_factor_state(&request, &context).await?;
                    harness.record("consumer:resolved", [("key".into(), state.key().into())]);
                    if !rearm {
                        return Ok(resolved(&state));
                    }
                    let attempt = begin_attempt(&state, &request, &context, 3).await?;
                    harness.record("consumer:attempt-consumed", []);
                    let result =
                        finish_attempt(attempt, scenario["restore"] != true, &context).await?;
                    harness.record(
                        "consumer:rearmed",
                        [("result".into(), harness.observe(&result)?)],
                    );
                    Ok(FieldMap::from([
                        ("verification".into(), resolved(&state)),
                        ("result".into(), result),
                    ])
                    .into())
                }
                .await;
                let accumulated = request.take_response_headers()?;
                harness.record(
                    "consumer:two-factor-finally",
                    [
                        ("headers".into(), headers(&accumulated)),
                        ("cookies".into(), cookies(&accumulated)),
                    ],
                );
                result
            },
        )
        .await;
    harness.finish(before, harness.outcome(result)?, &inner)
}

async fn proxy(scenario: &Json) -> AuthResult<Json> {
    let harness = Harness::new(scenario, "native-oauth-state")?;
    let plugin = OAuthProxyPlugin::with_config(OAuthProxyConfig {
        production_url: Some("https://production.verification-consumer.test".into()),
        current_url: Some(ORIGIN.into()),
        ..Default::default()
    });
    let (context, inner) = harness.context(&[&plugin]).await?;
    assert_eq!(
        context.config.account.store_state_strategy(),
        better_auth_core::OAuthStateStrategy::Database
    );
    let mut request = AuthRequest::new(HttpMethod::Post, "/sign-in/social");
    request.body = Some(serde_json::to_vec(&json!({"provider":"fixture"}))?);
    let returned = FieldValue::from(FieldMap::from([
        (
            "url".into(),
            "https://provider.verification-consumer.test/authorize?state=native-oauth-state&kept=1"
                .into(),
        ),
        ("redirect".into(), true.into()),
    ]));
    let mut response = AuthResponse::native(None, returned.clone());
    let before = harness.state(&inner)?;
    harness.activate();
    let harness = &harness;
    let result = context
        .with_native_context(
            better_auth_core::NativeRequest::default(),
            |context| async move {
                plugin
                    .after_request(&request, &mut response, &context)
                    .await?;
                let response = response.body.field_value()?;
                Ok(FieldMap::from([
                    ("result".into(), FieldValue::Undefined),
                    ("response".into(), response.clone()),
                    (
                        "sameResponse".into(),
                        response.strict_equals(&returned).into(),
                    ),
                ])
                .into())
            },
        )
        .await;
    harness.finish(before, harness.outcome(result)?, &inner)
}

fn business_contract(case: &Json) -> Json {
    let mut expected = case["runtime"].clone();
    let consumer = case["scenario"]["consumer"].as_str().unwrap();
    if expected["outcome"]["returned"] == true
        && matches!(consumer, "two-factor-resolve" | "two-factor-rearm")
    {
        let result = expected["outcome"]["result"].as_object_mut().unwrap();
        let verification = if consumer == "two-factor-rearm" {
            let attempt = result.shift_remove("attempt").unwrap();
            assert_eq!(
                attempt
                    .as_object()
                    .unwrap()
                    .keys()
                    .map(String::as_str)
                    .collect::<Vec<_>>(),
                ["recordFailure", "restore"]
            );
            for function in attempt.as_object().unwrap().values() {
                assert_eq!(function["type"], "function");
            }
            result
                .get_mut("verification")
                .unwrap()
                .as_object_mut()
                .unwrap()
        } else {
            result
        };
        let mut unpaired = Vec::new();
        for name in ["valid", "invalid", "beginAttempt"] {
            let function = verification.shift_remove(name).unwrap();
            assert_eq!(function["type"], "function");
            unpaired.push(function["identity"].clone());
        }
        if consumer == "two-factor-rearm" {
            let attempt = &case["runtime"]["outcome"]["result"]["attempt"];
            unpaired.extend([
                attempt["recordFailure"]["identity"].clone(),
                attempt["restore"]["identity"].clone(),
            ]);
        }
        expected["functionIds"]
            .as_array_mut()
            .unwrap()
            .retain(|identity| !unpaired.contains(identity));
        eprintln!(
            "{}: returned async helper identities remain unpaired: {unpaired:?}",
            case["name"]
        );
    }
    if consumer == "two-factor-trust" {
        let event = expected["events"]
            .as_array_mut()
            .unwrap()
            .last_mut()
            .unwrap();
        assert_eq!(event["phase"], "consumer:trust-finally");
        assert_eq!(
            event
                .as_object_mut()
                .unwrap()
                .shift_remove("newSessionSameObject"),
            Some(true.into())
        );
        eprintln!(
            "{}: NativeSessionData outer object identity remains unpaired; retained User identity is asserted separately",
            case["name"]
        );
    }
    expected
}

#[tokio::test]
async fn auth_consumers_match_upstream_business_runtime_with_explicit_unpaired_host_boundaries()
-> AuthResult<()> {
    let fixture: Json = serde_json::from_str(
        &std::fs::read_to_string(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../tests/fixtures/verification-auth-consumer-native-1.7.6.json"),
        )
        .unwrap(),
    )?;
    assert_eq!(fixture["version"], "1.7.6");
    let cases = fixture["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 63);
    let mut paired = 0;
    let mut failures = ReplayFailures::default();
    for case in cases {
        let name = case["name"].as_str().unwrap();
        if name == "oauth-proxy-truthy-value-key-error-is-logged" {
            failures.record(name, || {
                assert_eq!(case["scenario"]["keyError"], true);
                eprintln!(
                    "{name}: native OAuth Proxy secret getter remains unpaired by Option<String>"
                );
            });
            continue;
        }
        let scenario = &case["scenario"];
        let actual = match scenario["consumer"].as_str().unwrap() {
            "password-redirect" => password(scenario).await?,
            "two-factor-resolve" | "two-factor-rearm" => two_factor(scenario).await?,
            "two-factor-trust" => trust::capture(scenario).await?,
            "oauth-proxy" => proxy(scenario).await?,
            consumer => {
                return Err(AuthError::internal(format!(
                    "Unknown Auth consumer: {consumer}"
                )));
            }
        };
        failures.record(name, || {
            assert_replay(&actual, &business_contract(case), name)
        });
        paired += 1;
    }
    assert_eq!(paired, 62);
    failures.finish();
    Ok(())
}
