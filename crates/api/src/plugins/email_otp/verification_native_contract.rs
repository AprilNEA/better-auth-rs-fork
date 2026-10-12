#![expect(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::panic_in_result_fn,
    reason = "The pinned OTP contract requires every source case and complete business observation to match."
)]

use super::*;
use crate::plugins::{
    endpoint_context::EndpointContext,
    phone_number::{PhoneNumberApi, PhoneNumberPlugin},
    test_helpers::verification_consumer_native::{
        EMAIL, Harness, PHONE, ReplayFailures, assert_replay,
    },
};
use better_auth_core::{AuthError, AuthRequest, FieldMap, FieldValue, HttpMethod, NativeRequest};
use serde_json::{Value as Json, json};

async fn capture(scenario: &Json) -> AuthResult<Json> {
    let phone = scenario["consumer"] == "phone-consume";
    let identifier = if phone {
        PHONE.to_owned()
    } else {
        EmailOtpType::SignIn.identifier(EMAIL)
    };
    let harness = Harness::new(scenario, &identifier)?;
    let plugin = EmailOtpPlugin::with_config(EmailOtpConfig {
        expires_in: Duration::seconds(180),
        allowed_attempts: 3,
        storage: if scenario["hashed"] == true {
            EmailOtpStorage::Hashed
        } else {
            EmailOtpStorage::Plain
        },
        ..Default::default()
    });
    let phone_plugin = PhoneNumberPlugin::new();
    let (context, inner) = if phone {
        harness.context(&[&phone_plugin]).await?
    } else {
        harness.context(&[&plugin]).await?
    };
    let before = harness.state(&inner)?;
    harness.activate();
    let result = context.with_native_context(NativeRequest::default(), |context| async move {
        match scenario["consumer"].as_str().unwrap() {
            "email-get" => {
                let value = EmailOtpApi::from_context(&context)?.get_value(EMAIL, EmailOtpType::SignIn).await?;
                Ok(FieldMap::from([("otp".into(), value)]).into())
            }
            "email-check" => {
                let mut request = AuthRequest::new(HttpMethod::Post, "/email-otp/check-verification-otp");
                request.body = Some(serde_json::to_vec(&json!({
                    "email":EMAIL,"type":"sign-in","otp":if scenario["wrong"] == true {"000000"} else {"123456"},
                }))?);
                plugin.check(&request, &context).await?.body.field_value()
            }
            "email-reuse" => {
                let endpoint = EndpointContext::new(None, FieldValue::Undefined, &context);
                plugin.try_reuse_otp(&endpoint, &identifier).await
            }
            "phone-consume" => {
                let status = PhoneNumberApi::from_context(&context)?.consume(Some(json!({
                    "phoneNumber":PHONE,"code":if scenario["wrong"] == true {"000000"} else {"123456"},
                }))).await?;
                Ok(FieldMap::from([("status".into(), status.into())]).into())
            }
            consumer => Err(AuthError::internal(format!("Unknown native OTP consumer: {consumer}"))),
        }
    }).await;
    harness.finish(before, harness.outcome(result)?, &inner)
}

#[tokio::test]
async fn otp_consumers_match_upstream_business_runtime_with_host_stacks_unpaired() -> AuthResult<()>
{
    let fixture: Json = serde_json::from_str(
        &std::fs::read_to_string(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../tests/fixtures/verification-otp-consumer-native-1.7.6.json"),
        )
        .unwrap(),
    )?;
    assert_eq!(fixture["version"], "1.7.6");
    let cases = fixture["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 103);
    let mut failures = ReplayFailures::default();
    for case in cases {
        let name = case["name"].as_str().unwrap();
        let actual = capture(&case["scenario"]).await?;
        failures.record(name, || assert_replay(&actual, &case["runtime"], name));
    }
    failures.finish();
    Ok(())
}
