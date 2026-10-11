use super::*;
use better_auth_core::store::{EphemeralStore, schema::EntityRole};

pub(super) fn execution(
    state: &State,
    store: &EphemeralStore,
    outcome: &Value,
    events: &[Value],
    value: &FieldValue,
) -> AuthResult<()> {
    let scenario = &state.scenario;
    let subjects = events
        .iter()
        .filter(|event| event["kind"] == "subject")
        .count();
    assert!(
        events.iter().any(|event| event["kind"] == "get-user-info"),
        "{}",
        scenario.name
    );
    assert!(
        !events
            .iter()
            .any(|event| event["kind"] == "unexpected-social-mapper")
    );
    for event in events
        .iter()
        .filter(|event| event["kind"] == "subject" || event["kind"] == "mapper")
    {
        assert_eq!(
            event["sameProfile"], true,
            "{}: original callback profile",
            scenario.name
        );
    }
    let admissions = state.tracking.lock().unwrap().admissions.len();
    let users = store.storage_rows(EntityRole::User)?;
    let accounts = store.storage_rows(EntityRole::Account)?;
    let sessions = store.storage_rows(EntityRole::Session)?;
    if scenario.operation == "account-info" {
        assert_eq!(subjects, 0);
        assert_eq!(admissions, 0);
        assert!(!events.iter().any(|event| event["kind"] == "hook"));
        if scenario.shape == "response-spread-error" {
            assert_eq!(outcome["returned"], false);
            assert_eq!(outcome["originalError"], true);
        } else {
            assert_eq!(outcome["returned"], true);
            assert_eq!(
                value.model_property("account")?.json()?,
                Some(json!({
                    "id": "stored-account", "providerId": scenario.provider_id(), "accountId": "stored-provider-id",
                }))
            );
            if scenario.provider == "social" {
                assert_eq!(
                    value.as_object().unwrap().enumerable_keys()?,
                    [
                        "providerMeta",
                        "user",
                        "account",
                        "data",
                        "ownUndefined",
                        "tail"
                    ]
                );
                assert!(
                    value
                        .model_property("providerMeta")?
                        .strict_equals(&state.marker)
                );
                assert!(value.model_property("data")?.strict_equals(&state.raw));
                assert!(!value.as_object().unwrap().has_property("hidden")?);
            }
        }
    }
    if scenario.shape == "empty-email" || scenario.shape == "subject-error" {
        assert_eq!(
            subjects,
            usize::from(scenario.shape == "subject-error" || scenario.operation == "callback")
        );
        assert_eq!(admissions, 0);
        assert!(users.is_empty() && accounts.is_empty() && sessions.is_empty());
    }
    if scenario.shape == "identity" {
        assert_eq!(outcome["returned"], true);
        assert_eq!(outcome["status"], 302);
        assert_eq!(admissions, 1);
        assert_eq!(accounts.len(), 1);
        let account_id = accounts[0].get("accountId").unwrap();
        assert_eq!(account_id, &FieldValue::from("23"));
        assert!(!account_id.strict_equals(&state.mapped.model_property("id")?));
        assert!(
            state
                .raw
                .model_property("admissionMarker")?
                .strict_equals(&state.marker)
        );
    }
    if matches!(
        scenario.shape.as_str(),
        "native-business" | "falsy-defaults"
    ) {
        assert_eq!(outcome["returned"], true);
        assert_eq!((users.len(), accounts.len(), sessions.len()), (1, 1, 1));
        assert_eq!(
            accounts[0].get("accountId"),
            Some(&FieldValue::from("raw-account"))
        );
        if scenario.shape == "falsy-defaults" {
            assert_eq!(users[0].get("name"), Some(&FieldValue::from("")));
            assert_eq!(
                users[0].get("emailVerified"),
                Some(&FieldValue::from(false))
            );
            assert_eq!(users[0].get("image"), Some(&FieldValue::from(false)));
        }
    }
    if scenario.shape == "dynamic-email" {
        assert_eq!(subjects, 1);
        assert_eq!(outcome["returned"], false);
        assert_eq!(outcome["error"]["name"], "APIError");
        assert_eq!(outcome["error"]["message"], "");
        assert_eq!(outcome["error"]["properties"]["status"], "FOUND");
        assert_eq!(outcome["error"]["properties"]["statusCode"], 302);
        assert_eq!(outcome["originalError"], false);
        assert_eq!(admissions, 0);
        assert!(users.is_empty() && accounts.is_empty() && sessions.is_empty());
    }
    if scenario.operation != "helper" {
        return Ok(());
    }
    match scenario.shape.as_str() {
        "mapper-error" | "raw-getter-error" => {
            assert_eq!(outcome["returned"], false);
            assert_eq!(outcome["originalError"], true);
            assert_eq!(subjects, 0);
            assert!(
                !events
                    .iter()
                    .any(|event| event["kind"] == "own-keys" && event["object"] == "mapped")
            );
        }
        "scalar" => {
            assert_eq!(outcome["returned"], false);
            assert_eq!(outcome["error"]["message"], "OAUTH_ACCOUNT_SUBJECT_INVALID");
            assert_eq!(subjects, 1);
            assert_eq!(
                state.info().model_property("data")?,
                FieldValue::Number(7.0)
            );
            assert_eq!(
                state.info().model_property("user")?.enumerable_fields()?,
                fields([
                    ("email", FieldValue::Undefined),
                    ("emailVerified", FieldValue::Undefined),
                    ("image", FieldValue::Undefined),
                    ("name", FieldValue::Undefined),
                ])
            );
        }
        shape => {
            assert_eq!(outcome["returned"], true);
            assert_eq!(subjects, 1);
            let info = value.model_property("info")?;
            assert!(info.model_property("data")?.strict_equals(&state.raw));
            assert_eq!(
                value
                    .model_property("accountKey")?
                    .model_property("accountId")?,
                FieldValue::from("raw-account")
            );
            let user = info.model_property("user")?;
            if matches!(shape, "null" | "missing" | "getters") {
                assert!(user.as_object().unwrap().has_property("image")?);
                assert!(user.model_property("image")?.is_undefined());
            }
            if shape == "dynamic" {
                assert_eq!(
                    user.model_property("name")?.json()?,
                    Some(json!({"label": "Mapped"}))
                );
                assert_eq!(user.model_property("email")?, FieldValue::Number(9.0));
                assert_eq!(
                    user.model_property("emailVerified")?,
                    FieldValue::from("verified")
                );
                assert_eq!(user.model_property("image")?, FieldValue::Number(13.0));
            }
        }
    }
    Ok(())
}
