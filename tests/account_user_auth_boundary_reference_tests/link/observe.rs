use super::*;
use std::collections::{BTreeMap, BTreeSet};
use std::ops::RangeInclusive;

#[derive(Default)]
pub(super) struct Anchors {
    replacements: BTreeMap<String, String>,
    dates: BTreeMap<String, i64>,
    pub(super) encrypted_token: bool,
}

fn rows<'a>(snapshot: &'a Value, model: &str) -> TestResult<&'a [Value]> {
    snapshot[model]
        .as_array()
        .map(Vec::as_slice)
        .ok_or_else(|| format!("Expected {model} rows: {snapshot}").into())
}

fn millis(value: &Value) -> TestResult<i64> {
    let value = if value["type"] == "date" {
        &value["value"]
    } else {
        value
    };
    Ok(value
        .as_str()
        .ok_or("Expected Date observation or ISO timestamp")?
        .parse::<chrono::DateTime<chrono::Utc>>()?
        .timestamp_millis())
}

impl Anchors {
    pub(super) fn verify(
        events: &[Value],
        before: &Value,
        after: &Value,
        response: Option<&http::Response>,
        scenario: &Scenario,
        window: RangeInclusive<i64>,
    ) -> TestResult<Self> {
        for model in ["user", "session", "verification"] {
            assert_eq!(after[model], before[model], "Linking must preserve {model}");
        }
        let sessions = rows(before, "session")?;
        assert_eq!(sessions.len(), 1);
        assert_eq!(sessions[0]["token"], OWNER_TOKEN);
        let hooks: Vec<_> = events
            .iter()
            .filter(|event| event["kind"] == "hook" && event["model"] == "account")
            .collect();
        let mut anchors = Self::default();
        let mut tokens = BTreeSet::new();
        let seed_date = "2030-01-02T03:04:05Z"
            .parse::<chrono::DateTime<chrono::Utc>>()?
            .timestamp_millis();
        let before_accounts = rows(before, "account")?;
        let after_accounts = rows(after, "account")?;
        for row in hooks
            .iter()
            .map(|event| &event["data"])
            .chain(after_accounts.iter())
        {
            let Some(fields) = row.as_object() else {
                assert!(row.is_null(), "Account hook must return an object or null");
                continue;
            };
            for field in ["createdAt", "updatedAt"] {
                let Some(value) = fields
                    .get(field)
                    .filter(|value| !value.is_null() && value["type"] != "undefined")
                else {
                    continue;
                };
                let instant = millis(value)?;
                if instant == seed_date {
                    continue;
                }
                assert!(window.contains(&instant), "account.{field}: {value}");
                if let Some(previous) = anchors.dates.insert(field.into(), instant) {
                    assert_eq!(
                        previous, instant,
                        "Hooks and storage must retain one timestamp"
                    );
                }
            }
            if let Some(id) = fields.get("id").and_then(Value::as_str)
                && !before_accounts.iter().any(|seed| seed["id"] == id)
            {
                assert_eq!(id, "zz-link-account");
            }
            for field in ["accessToken", "refreshToken"] {
                if let Some(token) = fields
                    .get(field)
                    .and_then(Value::as_str)
                    .filter(|token| !token.is_empty() && !matches!(*token, "user-a" | "user-b"))
                {
                    let _ = tokens.insert(token.to_owned());
                }
            }
        }
        for token in &tokens {
            let plaintext = better_auth_core::utils::symmetric::decrypt(SECRET, token)?;
            assert_eq!(
                plaintext,
                if scenario.callback {
                    "callback-access"
                } else {
                    "direct-access"
                }
            );
            assert_ne!(token, &plaintext);
            let _ = anchors
                .replacements
                .insert(token.clone(), "<encrypted-access-token>".into());
        }
        assert!(
            tokens.len() <= 1,
            "Hooks and storage must retain one ciphertext per incoming token"
        );
        anchors.encrypted_token = !tokens.is_empty();
        if matches!(scenario.mode.as_str(), "success" | "after-error") {
            assert_eq!(
                after_accounts.len(),
                before_accounts.len() + usize::from(scenario.branch == "implicit")
            );
        } else {
            assert_eq!(after_accounts, before_accounts);
        }
        let after_hook = hooks.iter().any(|event| event["phase"] == "after");
        if matches!(scenario.mode.as_str(), "before-api" | "cancel") {
            assert!(!after_hook);
        }
        if scenario.mode == "after-error" {
            assert!(after_hook);
        }
        let mut cookies = response.map_or_else(Vec::new, |response| response.cookies.clone());
        for event in events {
            if let Some(values) = event.get("cookies") {
                for cookie in values.as_array().ok_or("Expected Cookie array")? {
                    cookies.push(cookie.as_str().ok_or("Expected Cookie string")?.to_owned());
                }
            }
        }
        for cookie in cookies {
            assert!(!cookie.starts_with("better-auth.account_data="));
            assert!(!cookie.starts_with("better-auth.session_token="));
        }
        Ok(anchors)
    }

    fn normalize_text(&self, text: &mut String) {
        let mut replacements: Vec<_> = self.replacements.iter().collect();
        replacements.sort_by_key(|(from, _)| std::cmp::Reverse(from.len()));
        for (from, to) in replacements {
            *text = text.replace(from, to);
        }
    }

    pub(super) fn normalize(&self, value: &mut Value) {
        match value {
            Value::String(text) => self.normalize_text(text),
            Value::Array(values) => values.iter_mut().for_each(|value| self.normalize(value)),
            Value::Object(values) => values.values_mut().for_each(|value| self.normalize(value)),
            _ => {}
        }
    }

    fn normalize_account(&self, row: &mut Value) -> TestResult {
        if let Some(fields) = row.as_object_mut() {
            for field in ["createdAt", "updatedAt"] {
                if let (Some(instant), Some(value)) = (self.dates.get(field), fields.get_mut(field))
                {
                    if value.is_null() || value["type"] == "undefined" {
                        continue;
                    }
                    if millis(value)? == *instant {
                        let label = format!("<account.{field}>");
                        *value = if value["type"] == "date" {
                            json!({"type": "date", "value": label})
                        } else {
                            json!(label)
                        };
                    }
                }
            }
        }
        self.normalize(row);
        Ok(())
    }

    pub(super) fn normalize_events(&self, events: &mut [Value]) -> TestResult {
        for event in events {
            if event["kind"] == "hook" && event["model"] == "account" {
                self.normalize_account(&mut event["data"])?;
            }
            self.normalize(event);
        }
        Ok(())
    }

    pub(super) fn normalize_storage(&self, snapshot: &mut Value) -> TestResult {
        for row in snapshot["account"]
            .as_array_mut()
            .ok_or("Account table missing")?
        {
            self.normalize_account(row)?;
        }
        Ok(())
    }

    pub(super) fn normalize_response(&self, response: &mut http::Response) {
        for [_, value] in &mut response.headers {
            self.normalize_text(value);
        }
        for cookie in &mut response.cookies {
            self.normalize_text(cookie);
        }
        self.normalize_text(&mut response.body);
    }
}

pub(super) fn assert_events(actual: &[Value], case: &LinkCase, scenario: &Scenario) -> TestResult {
    let console: Vec<_> = case
        .events
        .iter()
        .filter(|event| event["kind"] == "console.error")
        .cloned()
        .collect();
    if scenario.mode == "after-error" && scenario.invocation == "http" {
        assert_eq!(
            console,
            vec![
                json!({"kind": "console.error", "args": ["# SERVER_ERROR: ", {"name": "Error", "message": "link runtime failure", "properties": {}, "keys": []}]})
            ]
        );
        let [.., error, diagnostic] = case.events.as_slice() else {
            return Err("Missing HTTP runtime error diagnostics".into());
        };
        assert_eq!(error["kind"], "api-error");
        assert_eq!(diagnostic["kind"], "console.error");
        assert!(
            actual
                .iter()
                .any(|event| event["kind"] == "api-error" && event["error"]["sameObject"] == true)
        );
    } else {
        assert!(
            console.is_empty(),
            "Unexpected upstream diagnostics: {console:?}"
        );
    }
    let expected: Vec<_> = case
        .events
        .iter()
        .filter(|event| event["kind"] != "console.error")
        .cloned()
        .collect();
    recorder::assert_provider_token_keys(actual, &expected, case);
    assert_eq!(
        actual, expected,
        "{case:?}: complete ordered callbacks, keys, queries, native errors, and Cookie visibility"
    );
    Ok(())
}
