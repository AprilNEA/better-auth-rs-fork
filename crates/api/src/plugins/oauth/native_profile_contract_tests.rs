//! Strict replay of the 20 pinned native provider scenarios and observable property operations.
//! Generated dates require bounded runtime observation; provider values and events remain exact.
#![expect(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::panic_in_result_fn,
    clippy::panic,
    reason = "Contract inputs and complete observations must fail immediately on mismatches."
)]

use better_auth_core::{AuthError, AuthResult, FieldMap, FieldValue};
use serde_json::{Value, json};
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

#[path = "native_profile_contract/assertions.rs"]
mod assertions;
#[path = "native_profile_contract/callbacks.rs"]
mod callbacks;
#[path = "native_profile_contract/capture.rs"]
mod capture;
#[path = "native_profile_contract/endpoint.rs"]
mod endpoint;
#[path = "native_profile_contract/harness.rs"]
mod harness;
#[path = "native_profile_contract/headers.rs"]
mod headers;
#[path = "native_profile_contract/helper.rs"]
mod helper;
#[path = "native_profile_contract/hooks.rs"]
mod hooks;
#[path = "native_profile_contract/observe.rs"]
mod observe;
#[path = "native_profile_contract/server.rs"]
mod server;
#[path = "native_profile_contract/source.rs"]
mod source;
#[path = "native_profile_contract/state.rs"]
mod state;

use state::{Scenario, State};

const ORIGIN: &str = "http://oauth-native-profile.test";
const SECRET: &str = "oauth-native-profile-contract-secret-at-least-thirty-two-characters";
const EMAIL: &str = "Owner@oauth-native-profile.test";
const DATE: &str = "2030-01-02T03:04:05.000Z";
const TIMESTAMP: i64 = 1_893_553_445_000;
const ACCESS_TOKEN: &str = "native-profile-access";
const ID_TOKEN: &str = "native-profile-id-token";

fn fields<const N: usize>(entries: [(&str, FieldValue); N]) -> FieldMap {
    entries
        .into_iter()
        .map(|(key, value)| (key.into(), value))
        .collect()
}

fn object<const N: usize>(entries: [(&str, FieldValue); N]) -> FieldValue {
    fields(entries).into()
}

fn fixture() -> Value {
    let fixture: Value = serde_json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../tests/fixtures/oauth-native-profile-1.7.6.json"
    )))
    .unwrap();
    assert_eq!(fixture["version"], "1.7.6");
    assert_eq!(fixture["cases"].as_array().unwrap().len(), 20);
    assert_eq!(fixture["scenarios"].as_array().unwrap().len(), 20);
    for group in ["cases", "scenarios"] {
        assert_eq!(
            fixture[group]
                .as_array()
                .unwrap()
                .iter()
                .map(|scenario| scenario["name"].as_str().unwrap())
                .collect::<Vec<_>>(),
            CASE_NAMES
        );
    }
    fixture
}

macro_rules! native_profiles {
    ($($name:ident => $capture:ident: $scenario:literal),+ $(,)?) => {
        const CASE_NAMES: &[&str] = &[$($scenario),+];
        $(
            #[tokio::test]
            async fn $name() {
                let fixture = fixture();
                let expected = fixture["cases"].as_array().unwrap().iter()
                    .find(|case| case["name"] == $scenario).unwrap();
                let scenario: Scenario = serde_json::from_value(expected.clone()).unwrap();
                let actual = $capture::capture(scenario).await.unwrap();
                capture::assert_complete(&actual, expected, $scenario);
            }
        )+
    }
}

native_profiles! {
    generic_helper_dynamic => helper: "generic-helper-dynamic",
    generic_helper_missing => helper: "generic-helper-missing",
    generic_helper_null => helper: "generic-helper-null",
    generic_helper_scalar_profile => helper: "generic-helper-scalar-profile",
    generic_helper_getters => helper: "generic-helper-getters",
    generic_helper_mapper_error => helper: "generic-helper-mapper-error",
    generic_helper_raw_getter_error => helper: "generic-helper-raw-getter-error",
    generic_callback_identity => endpoint: "generic-callback-identity",
    generic_callback_native_business => endpoint: "generic-callback-native-business",
    generic_callback_empty_email => endpoint: "generic-callback-empty-email",
    generic_callback_mapper_error => endpoint: "generic-callback-mapper-error",
    social_callback_empty_email => endpoint: "social-callback-empty-email",
    social_direct_empty_email => endpoint: "social-direct-empty-email",
    social_callback_subject_error => endpoint: "social-callback-subject-error",
    social_direct_subject_error => endpoint: "social-direct-subject-error",
    social_direct_dynamic_email => endpoint: "social-direct-dynamic-email",
    social_direct_falsy_defaults => endpoint: "social-direct-falsy-defaults",
    generic_account_info_dynamic => endpoint: "generic-account-info-dynamic",
    social_account_info_response_spread => endpoint: "social-account-info-response-spread",
    social_account_info_spread_error => endpoint: "social-account-info-spread-error",
}
