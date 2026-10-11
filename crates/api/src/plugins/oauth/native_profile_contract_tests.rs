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
#[path = "native_profile_contract/helper.rs"]
mod helper;
#[path = "native_profile_contract/observe.rs"]
mod observe;
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
    fixture
}

#[tokio::test]
async fn native_profile_contract_helpers_match_upstream() {
    let fixture = fixture();
    let mut count = 0;
    for expected in fixture["cases"].as_array().unwrap() {
        let scenario: Scenario = serde_json::from_value(expected.clone()).unwrap();
        if scenario.operation != "helper" {
            continue;
        }
        let actual = helper::capture(scenario.clone()).await.unwrap();
        capture::assert_complete(&actual, expected, &scenario.name);
        count += 1;
    }
    assert_eq!(count, 7);
}
