//! Paired with google-github-native.test.mjs using complete native provider responses.
#![expect(
    clippy::unwrap_used,
    reason = "Contract tests must fail immediately when provider reads or native identities change."
)]

use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use better_auth_core::{AuthError, AuthResult, FieldMap, FieldValue, SchemaValue};
use serde_json::{Value, json};

use crate::plugins::oauth::{
    OAuthProfileMapper, OAuthProvider, OAuthUserInfoRequest,
    resolved::ResolvedProvider,
    social_profile::{ProviderProfile, fetch_user_info_from_provider},
};

#[path = "google_github_native_support.rs"]
mod support;
use support::{Action, Probe, Run, invoke, run};

fn object<const N: usize>(fields: [(&str, FieldValue); N]) -> FieldValue {
    fields
        .into_iter()
        .map(|(key, value)| (key.into(), value))
        .collect::<FieldMap>()
        .into()
}

fn keys(value: &FieldValue) -> Vec<String> {
    value.as_object().unwrap().enumerable_keys().unwrap()
}

fn base(id: &str) -> Value {
    if id == "google" {
        json!({"sub":"google-native", "name":"Before", "email":"before@example.test", "picture":"before.png", "email_verified":true})
    } else {
        json!({"id":42, "login":"octocat", "name":"Before", "email":null, "avatar_url":"before.png"})
    }
}

fn selected_emails() -> Value {
    json!([
        {"email":"before@example.test", "primary":"primary", "verified":{"original":true}},
        {"email":"after@example.test", "primary":false, "verified":false}
    ])
}

fn prepared(id: &str) -> FieldValue {
    let raw: FieldValue = base(id).into();
    if id == "github" {
        raw.as_object()
            .unwrap()
            .set("email", "before@example.test".into())
            .unwrap();
    }
    raw
}

fn expect_response(actual: &Run, user: FieldValue, data: FieldValue) -> FieldValue {
    let response = &actual.result.as_ref().unwrap().value;
    assert_eq!(
        response,
        &object([("user", user.clone()), ("data", data.clone())])
    );
    assert_eq!(keys(response), ["user", "data"]);
    let actual_user = response.model_property("user").unwrap();
    let actual_data = response.model_property("data").unwrap();
    assert_eq!(keys(&actual_user), keys(&user));
    assert_eq!(keys(&actual_data), keys(&data));
    assert!(actual_data.strict_equals(&actual.probe.raw()));
    actual_user
}

fn expected_events(id: &str) -> Vec<&'static str> {
    if id == "google" {
        vec!["mapper"]
    } else {
        vec!["profile", "emails", "mapper"]
    }
}

#[tokio::test]
async fn google_keeps_missing_null_and_dynamic_claims_without_narrowing() {
    for fields in [
        json!({}),
        json!({"name":null, "email":null, "picture":null, "email_verified":null}),
        json!({"name":["Native",3], "email":17, "picture":{"url":"native.png"}, "email_verified":"verified"}),
    ] {
        let mut profile = json!({"sub":"google-native"});
        profile
            .as_object_mut()
            .unwrap()
            .extend(fields.as_object().unwrap().clone());
        profile
            .as_object_mut()
            .unwrap()
            .insert("extension".into(), json!({"kept":true}));
        let actual = run("google", profile.clone(), json!([]), Action::Observe).await;
        let data: FieldValue = profile.into();
        let user = expect_response(
            &actual,
            object([
                ("name", data.model_property("name").unwrap()),
                ("email", data.model_property("email").unwrap()),
                ("image", data.model_property("picture").unwrap()),
                (
                    "emailVerified",
                    data.model_property("email_verified").unwrap(),
                ),
            ]),
            data.clone(),
        );
        assert_eq!(*actual.probe.events.lock().unwrap(), ["mapper"]);
        assert_eq!(*actual.probe.before.lock().unwrap(), [data]);
        for (user_field, raw_field) in [("name", "name"), ("image", "picture")] {
            assert!(
                user.model_property(user_field)
                    .unwrap()
                    .strict_equals(&actual.probe.raw().model_property(raw_field).unwrap())
            );
        }
        assert_eq!(keys(&user), ["name", "email", "image", "emailVerified"]);
    }
}

#[tokio::test]
async fn google_falsy_id_token_skips_http_and_mapper() {
    for id_token in [
        SchemaValue::Undefined,
        SchemaValue::Dynamic(FieldValue::Undefined),
        SchemaValue::Dynamic(FieldValue::Null),
        SchemaValue::Dynamic(false.into()),
        SchemaValue::Dynamic(0.0.into()),
        Some(String::new()).into(),
    ] {
        let probe = Probe::new("google", Action::Throw);
        let mut config = OAuthProvider::google("client", "secret");
        config.user_info_url = None;
        let actual = invoke(
            config,
            OAuthUserInfoRequest {
                id_token,
                access_token: Some("native-profile-token".into()).into(),
                ..Default::default()
            },
            probe,
        )
        .await;
        assert!(actual.result.unwrap().value.is_null());
        assert!(actual.probe.events.lock().unwrap().is_empty());
        assert!(actual.probe.inputs.lock().unwrap().is_empty());
    }
}

#[tokio::test]
async fn defaults_read_mapper_mutations_without_recomputing_github_verification() {
    for id in ["google", "github"] {
        let actual = run(id, base(id), selected_emails(), Action::Mutate).await;
        let shared = &actual.probe.shared;
        let data: FieldValue = base(id).into();
        let raw = data.as_object().unwrap();
        raw.set(
            "name",
            if id == "google" {
                shared.clone()
            } else {
                0.0.into()
            },
        )
        .unwrap();
        raw.set("email", shared.clone()).unwrap();
        raw.set(
            if id == "google" {
                "picture"
            } else {
                "avatar_url"
            },
            FieldValue::Undefined,
        )
        .unwrap();
        if id == "google" {
            raw.set("email_verified", 0.0.into()).unwrap();
        } else {
            raw.set("login", shared.clone()).unwrap();
        }
        raw.set("ownUndefined", FieldValue::Undefined).unwrap();
        let user = expect_response(
            &actual,
            object([
                ("name", shared.clone()),
                ("email", shared.clone()),
                ("image", FieldValue::Undefined),
                (
                    "emailVerified",
                    if id == "google" {
                        0.0.into()
                    } else {
                        json!({"original":true}).into()
                    },
                ),
                ("mappedExtra", shared.clone()),
                ("mappedUndefined", FieldValue::Undefined),
            ]),
            data,
        );
        assert_eq!(*actual.probe.events.lock().unwrap(), expected_events(id));
        assert_eq!(*actual.probe.before.lock().unwrap(), [prepared(id)]);
        for field in ["name", "email", "mappedExtra"] {
            assert!(user.model_property(field).unwrap().strict_equals(shared));
        }
        shared
            .as_object()
            .unwrap()
            .set("marker", "after-return".into())
            .unwrap();
        assert_eq!(
            user.model_property("name")
                .unwrap()
                .model_property("marker")
                .unwrap(),
            FieldValue::from("after-return")
        );
        assert_eq!(
            actual
                .probe
                .raw()
                .model_property("email")
                .unwrap()
                .model_property("marker")
                .unwrap(),
            FieldValue::from("after-return")
        );
    }
}

#[tokio::test]
async fn mapper_spread_replaces_complete_fields_including_undefined_and_null() {
    for id in ["google", "github"] {
        let actual = run(id, base(id), selected_emails(), Action::Overlay).await;
        let shared = &actual.probe.shared;
        let user = expect_response(
            &actual,
            object([
                ("name", FieldValue::Undefined),
                ("email", FieldValue::Null),
                ("image", shared.clone()),
                ("emailVerified", "mapped".into()),
                ("extra", shared.clone()),
            ]),
            prepared(id),
        );
        assert!(user.model_property("image").unwrap().strict_equals(shared));
        assert!(user.model_property("extra").unwrap().strict_equals(shared));
    }
}

#[tokio::test]
async fn mapper_and_spread_errors_preserve_the_original_value_and_callback_order() {
    for id in ["google", "github"] {
        for action in [Action::Throw, Action::SpreadThrow] {
            let actual = run(id, base(id), selected_emails(), action).await;
            assert!(
                actual
                    .result
                    .unwrap_err()
                    .raw_value()
                    .unwrap()
                    .strict_equals(&actual.probe.failure)
            );
            assert_eq!(actual.probe.inputs.lock().unwrap().len(), 1);
            assert_eq!(actual.probe.raw(), prepared(id));
            let mut events = expected_events(id);
            if matches!(action, Action::SpreadThrow) {
                events.extend(["spread:extra", "spread:email"]);
            }
            assert_eq!(*actual.probe.events.lock().unwrap(), events);
        }
    }
}

#[tokio::test]
async fn github_uses_primary_truthiness_and_retains_dynamic_verified_values() {
    for (primary, verified, expected) in [
        (
            json!("primary"),
            Some(json!({"checked":true})),
            json!({"checked":true}),
        ),
        (json!([]), Some(json!([])), json!([])),
        (json!({}), Some(json!("yes")), json!("yes")),
        (json!(2), Some(json!(0)), json!(0)),
        (json!(true), Some(json!("")), json!("")),
        (json!(true), Some(Value::Null), json!(false)),
        (json!(true), None, json!(false)),
    ] {
        let mut profile = base("github");
        profile
            .as_object_mut()
            .unwrap()
            .insert("email".into(), json!(0));
        let mut selected = json!({"email":"primary@example.test", "primary":primary});
        if let Some(verified) = verified {
            selected
                .as_object_mut()
                .unwrap()
                .insert("verified".into(), verified);
        }
        let emails = json!([
            {"email":"secondary@example.test", "primary":0, "verified":false},
            selected
        ]);
        let actual = run("github", profile.clone(), emails, Action::Observe).await;
        let data: FieldValue = profile.into();
        data.as_object()
            .unwrap()
            .set("email", "primary@example.test".into())
            .unwrap();
        expect_response(
            &actual,
            object([
                ("name", "Before".into()),
                ("email", "primary@example.test".into()),
                ("image", "before.png".into()),
                ("emailVerified", expected.into()),
            ]),
            data.clone(),
        );
        assert_eq!(
            *actual.probe.events.lock().unwrap(),
            expected_events("github")
        );
        assert_eq!(*actual.probe.before.lock().unwrap(), [data]);
    }
}

#[tokio::test]
async fn github_keeps_native_inline_email_and_uses_strict_equality() {
    for (email, matched, expected) in [
        (json!(17), json!(17), json!("verified")),
        (json!(17), json!("17"), json!(false)),
        (
            json!({"address":"same"}),
            json!({"address":"same"}),
            json!(false),
        ),
    ] {
        let mut profile = base("github");
        profile
            .as_object_mut()
            .unwrap()
            .insert("email".into(), email.clone());
        let actual = run(
            "github",
            profile.clone(),
            json!([{"email":matched, "primary":true, "verified":"verified"}]),
            Action::Observe,
        )
        .await;
        let user = expect_response(
            &actual,
            object([
                ("name", "Before".into()),
                ("email", email.into()),
                ("image", "before.png".into()),
                ("emailVerified", expected.into()),
            ]),
            profile.into(),
        );
        assert!(
            user.model_property("email")
                .unwrap()
                .strict_equals(&actual.probe.raw().model_property("email").unwrap())
        );
        assert_eq!(
            *actual.probe.events.lock().unwrap(),
            expected_events("github")
        );
    }
}

#[tokio::test]
async fn github_empty_email_list_writes_own_undefined_before_mapper() {
    for initial in [None, Some(Value::Null), Some(json!(""))] {
        let mut profile = base("github");
        profile.as_object_mut().unwrap().remove("email");
        if let Some(initial) = initial {
            profile
                .as_object_mut()
                .unwrap()
                .insert("email".into(), initial);
        }
        let actual = run("github", profile.clone(), json!([]), Action::Observe).await;
        let data: FieldValue = profile.into();
        data.as_object()
            .unwrap()
            .set("email", FieldValue::Undefined)
            .unwrap();
        expect_response(
            &actual,
            object([
                ("name", "Before".into()),
                ("email", FieldValue::Undefined),
                ("image", "before.png".into()),
                ("emailVerified", false.into()),
            ]),
            data.clone(),
        );
        assert_eq!(*actual.probe.before.lock().unwrap(), [data]);
        assert_eq!(
            *actual.probe.events.lock().unwrap(),
            expected_events("github")
        );
    }
}
