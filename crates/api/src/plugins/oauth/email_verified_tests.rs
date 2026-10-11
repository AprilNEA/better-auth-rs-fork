#![expect(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::panic,
    reason = "Contract fixtures fail immediately on invalid captured data or changed provider results."
)]

use super::*;
use better_auth_core::{FieldValue, SchemaValue};
use serde_json::Value;

#[test]
fn default_email_verified_presence_matches_upstream() {
    let fixture: Value = serde_json::from_str(include_str!(
        "../../../../../tests/fixtures/email-verified-presence-1.7.6.json"
    ))
    .unwrap();
    for case in fixture["cases"].as_array().unwrap() {
        let id = case["provider"].as_str().unwrap();
        if id == "generic" || case["mapping"] != "unchanged" {
            continue;
        }
        let provider = match id {
            "discord" => OAuthProvider::discord("client", "secret"),
            "huggingface" => OAuthProvider::huggingface("client", "secret"),
            "reddit" => OAuthProvider::reddit("client", "secret"),
            _ => panic!("unknown fixture provider"),
        };
        let definition = &fixture["profiles"][id];
        let field = definition["field"].as_str().unwrap();
        let mut profile = definition["profile"].clone();
        if case["raw"] == "omitted" {
            let _ = profile.as_object_mut().unwrap().remove(field);
        } else {
            profile[field] = serde_json::from_str(case["raw"].as_str().unwrap()).unwrap();
        }
        let profile = provider.http_profile_data(profile).unwrap().unwrap();
        let user = provider.decode_profile(profile).unwrap().unwrap();
        let expected = &case["expected"]["user"];
        let value = user.into_native().model_property("emailVerified").unwrap();
        let output = better_auth_core::FieldMap::from([("emailVerified".into(), value)])
            .json()
            .unwrap();
        let output = Value::Object(output);
        assert_eq!(output, *expected, "{id}/{}", case["raw"]);
    }
}

#[test]
fn verification_status_requires_boolean_true() {
    for (field, verified) in [
        (SchemaValue::Undefined, false),
        (SchemaValue::Typed(None), false),
        (SchemaValue::Typed(Some(false)), false),
        (SchemaValue::Typed(Some(true)), true),
        (SchemaValue::Dynamic(FieldValue::Null), false),
        (SchemaValue::Dynamic(FieldValue::Bool(false)), false),
        (SchemaValue::Dynamic(FieldValue::Bool(true)), true),
    ] {
        assert_eq!(providers::profile_email_verified(&field).unwrap(), verified);
    }
}
