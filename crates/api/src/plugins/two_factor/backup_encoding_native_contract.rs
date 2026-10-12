#![expect(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "Pinned encoding contracts must fail immediately on invalid fixture shapes or callback observations."
)]

use super::*;
use crate::plugins::test_helpers::{
    native_observation::NativeObservation,
    verification_consumer_native::{ReplayFailures, SECRET, assert_replay, object::Root},
};
use better_auth_core::{FieldFunction, SecretKey, VersionedSecret};
use serde_json::{Value as Json, json};
use std::sync::Mutex;

async fn capture_encoding(scenario: &Json) -> AuthResult<Json> {
    let observer = Arc::new(Mutex::new(NativeObservation::default()));
    let root = Root::new(if scenario["value"] == "function" {
        "function"
    } else {
        "object"
    });
    if scenario["value"] == "object" {
        root.data("marker", "native-generated-codes".into());
        let expected = root.owner();
        let observed = observer.clone();
        let method: FieldValue = FieldFunction::contextual(move |receiver, arguments| {
            let owner = expected.upgrade().unwrap();
            let same_receiver = receiver.strict_equals(owner.get().unwrap());
            assert!(same_receiver);
            assert_eq!(arguments, &[FieldValue::from("")]);
            let mut observer = observed.lock().unwrap();
            let key = observer.observe(&arguments[0])?;
            observer.record(
                "toJSON",
                [
                    ("sameReceiver".into(), same_receiver.into()),
                    ("key".into(), key),
                ],
            );
            Ok(FieldValue::Undefined)
        })
        .into();
        root.getter("toJSON", false, move |_| Ok(method.clone()));
    }
    let before = observer.lock().unwrap().observe(&root.value)?;
    let keys = [VersionedSecret::new(3, SECRET)];
    let key = if scenario["key"] == "single" {
        SecretKey::Single(SECRET)
    } else {
        SecretKey::Versioned {
            keys: &keys,
            legacy_secret: None,
        }
    };
    let storage = if scenario["storage"] == "plain" {
        BackupCodeStorage::Plain
    } else {
        BackupCodeStorage::Encrypted
    };
    let result = storage.encode(&root.value, key).await;
    let mut observer = observer.lock().unwrap();
    let outcome = match result {
        Ok(value) => json!({"returned":true,"result":observer.observe(&value)?}),
        Err(error) => {
            let error = error.into_thrown_value()?;
            json!({"returned":false,"error":{
                "name":observer.observe(&error.model_property("name")?)?,
                "message":observer.observe(&error.model_property("message")?)?,
                "ownEnumerable":observer.observe(&error)?,
            }})
        }
    };
    Ok(
        json!({"before":before,"events":observer.events,"outcome":outcome,
        "after":observer.observe(&root.value)?}),
    )
}

fn encoder_boundary(source: &Json) -> Json {
    let mut expected = source.clone();
    let events = expected["events"].as_array_mut().unwrap();
    assert_eq!(events.remove(0), json!({"phase":"generate"}));
    if expected["outcome"]["returned"] == true {
        assert_eq!(expected["outcome"]["sameCodes"], true);
        assert_eq!(
            expected["outcome"]["result"]["backupCodes"],
            expected["before"]
        );
        let result = expected["outcome"]["result"]["encryptedBackupCodes"].clone();
        expected["outcome"] = json!({"returned":true,"result":result});
    }
    expected
}

#[tokio::test]
async fn backup_code_encoding_matches_native_callbacks_and_undefined_boundary() -> AuthResult<()> {
    let fixture: Json = serde_json::from_str(
        &std::fs::read_to_string(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../tests/fixtures/two-factor-backup-code-encoding-1.7.6.json"),
        )
        .unwrap(),
    )?;
    assert_eq!(fixture["version"], "1.7.6");
    assert_eq!(fixture["contract"], "two-factor-backup-code-encoding");
    let cases = fixture["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 4);
    let mut failures = ReplayFailures::default();
    for case in cases {
        let name = case["name"].as_str().unwrap();
        let actual = super::backup_code_native_contract::capture(&case["scenario"]).await?;
        failures.record(name, || assert_replay(&actual, &case["runtime"], name));
    }
    // The source generator wrapper remains unpaired; Rust's generator returns Vec<String>.
    // Compare only the actual native encoder boundary without fabricating a generation callback.
    eprintln!(
        "Dynamic generation callback and result-wrapper identity remain unpaired; the complete source observation is retained."
    );
    let encodings = fixture["encodings"].as_array().unwrap();
    assert_eq!(encodings.len(), 4);
    for case in encodings {
        let name = case["name"].as_str().unwrap();
        let actual = capture_encoding(&case["scenario"]).await?;
        failures.record(name, || {
            assert_replay(&actual, &encoder_boundary(&case["runtime"]), name)
        });
    }
    failures.finish();
    Ok(())
}
