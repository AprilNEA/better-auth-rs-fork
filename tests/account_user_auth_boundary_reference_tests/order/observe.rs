use super::*;
use std::collections::{BTreeMap, BTreeSet};
use std::ops::RangeInclusive;

#[derive(Default)]
pub(super) struct Anchors {
    replacements: BTreeMap<String, String>,
    dates: BTreeMap<String, i64>,
    pub(super) encrypted_token: bool,
    pub(super) token: Option<String>,
    pub(super) account_cookies: Vec<Value>,
}

fn millis(value: &Value) -> TestResult<i64> {
    let text = if value["type"] == "date" {
        &value["value"]
    } else {
        value
    };
    Ok(text
        .as_str()
        .ok_or("Expected Date observation or ISO timestamp")?
        .parse::<chrono::DateTime<chrono::Utc>>()?
        .timestamp_millis())
}

fn text<'a>(value: &'a Value, field: &str) -> TestResult<&'a str> {
    value[field]
        .as_str()
        .ok_or_else(|| format!("Expected string {field}: {value}").into())
}

fn rows<'a>(value: &'a Value, model: &str) -> TestResult<&'a [Value]> {
    value[model]
        .as_array()
        .map(Vec::as_slice)
        .ok_or_else(|| format!("Expected {model} rows: {value}").into())
}

fn hook<'a>(events: &'a [Value], model: &str, phase: &str) -> Option<&'a Value> {
    super::super::observe::hook(events, model, phase)
}

fn all_cookies(events: &[Value], response: &http::Response) -> TestResult<Vec<String>> {
    let mut cookies = response.cookies.clone();
    for event in events {
        if let Some(values) = event.get("cookies") {
            for value in values.as_array().ok_or("Expected Cookie array")? {
                cookies.push(value.as_str().ok_or("Expected Cookie string")?.into());
            }
        }
    }
    Ok(cookies)
}

impl Anchors {
    pub(super) fn verify(
        events: &[Value],
        before: &Value,
        after: &Value,
        response: &http::Response,
        scenario: &Scenario,
        window: RangeInclusive<i64>,
    ) -> TestResult<Self> {
        let mut anchors = Self::default();
        let mut tokens = BTreeSet::new();
        let seed_date = "2030-01-02T03:04:05Z"
            .parse::<chrono::DateTime<chrono::Utc>>()?
            .timestamp_millis();
        for model in ["user", "account", "session"] {
            for row in events
                .iter()
                .filter(|event| event["kind"] == "hook" && event["model"] == model)
                .map(|event| &event["data"])
                .chain(rows(after, model)?.iter())
            {
                let Some(fields) = row.as_object() else {
                    continue;
                };
                for field in ["createdAt", "updatedAt", "expiresAt"] {
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
                    let base = if field == "expiresAt" {
                        instant - 3_600_000
                    } else {
                        instant
                    };
                    assert!(window.contains(&base), "{model}.{field}: {value}");
                    if let Some(previous) =
                        anchors.dates.insert(format!("{model}.{field}"), instant)
                    {
                        assert_eq!(
                            previous, instant,
                            "Callback and stored timestamp must agree"
                        );
                    }
                }
                if model == "account"
                    && let Some(token) = fields
                        .get("accessToken")
                        .and_then(Value::as_str)
                        .filter(|token| !matches!(*token, "user-a" | "user-b"))
                {
                    let _ = tokens.insert(token.to_owned());
                }
                if let Some(id) = fields.get("id").and_then(Value::as_str)
                    && !rows(before, model)?.iter().any(|seed| seed["id"] == id)
                {
                    assert_eq!(id, format!("zz-order-{model}"));
                    let _ = anchors
                        .replacements
                        .insert(id.into(), format!("<{model}-id>"));
                }
            }
        }
        let issued = hook(events, "session", "before");
        let complete = hook(events, "session", "after");
        assert_eq!(
            issued.is_some(),
            matches!(scenario.mode.as_str(), "success" | "update-disabled")
        );
        assert_eq!(complete.is_some(), issued.is_some());
        assert_eq!(rows(after, "session")?.len(), usize::from(issued.is_some()));
        if let Some(issued) = issued {
            let token = text(issued, "token")?;
            assert_eq!(token.len(), 32);
            assert!(token.bytes().all(|byte| byte.is_ascii_alphanumeric()));
            assert_eq!(
                complete.ok_or("Session after hook missing")?["token"],
                token
            );
            assert_eq!(rows(after, "session")?[0]["token"], token);
            assert_eq!(
                issued["userId"],
                if scenario.branch == "new" {
                    "zz-order-user"
                } else {
                    "user-a"
                }
            );
            anchors.token = Some(token.into());
            let _ = anchors
                .replacements
                .insert(token.into(), "<session-token>".into());
        }
        for model in ["user", "account", "session"] {
            if let (Some(created), Some(updated)) = (
                anchors.dates.get(&format!("{model}.createdAt")),
                anchors.dates.get(&format!("{model}.updatedAt")),
            ) {
                assert!(created <= updated, "{model} timestamp evaluation order");
            }
        }
        if let (Some(user_updated), Some(account_created)) = (
            anchors.dates.get("user.updatedAt"),
            anchors.dates.get("account.createdAt"),
        ) {
            assert!(user_updated <= account_created);
        }
        if issued.is_some() {
            if let Some(account_updated) = anchors.dates.get("account.updatedAt") {
                assert!(account_updated <= &anchors.dates["session.createdAt"]);
            }
            assert!(
                anchors.dates["session.expiresAt"] - 3_600_000
                    <= anchors.dates["session.createdAt"]
            );
        }
        let cookies = all_cookies(events, response)?;
        let account_cookies: BTreeSet<_> = cookies
            .iter()
            .filter(|cookie| cookie.starts_with("better-auth.account_data="))
            .collect();
        let expected_cookie = scenario.mode != "cookie-failure"
            && (scenario.branch == "existing" || !scenario.mode.starts_with("raw-"));
        assert_eq!(account_cookies.len(), usize::from(expected_cookie));
        for cookie in account_cookies {
            let (pair, attributes) = cookie
                .split_once(';')
                .ok_or("Account Cookie attributes missing")?;
            assert_eq!(attributes, " Max-Age=300; Path=/; HttpOnly; SameSite=Lax");
            let token = pair
                .strip_prefix("better-auth.account_data=")
                .ok_or("Account Cookie prefix missing")?;
            let mut claims =
                better_auth_core::utils::jwe::decode(token, SECRET, "better-auth-account")
                    .ok_or("Account Cookie decryption failed")?;
            let keys: Vec<_> = claims.keys().cloned().collect();
            let iat = claims
                .remove("iat")
                .and_then(|value| value.as_i64())
                .ok_or("Cookie iat missing")?;
            let exp = claims
                .remove("exp")
                .and_then(|value| value.as_i64())
                .ok_or("Cookie exp missing")?;
            let jti = claims
                .remove("jti")
                .and_then(|value| value.as_str().map(str::to_owned))
                .ok_or("Cookie jti missing")?;
            assert!((window.start() / 1000..=window.end() / 1000).contains(&iat));
            assert!((window.start() / 1000..=window.end() / 1000).contains(&(exp - 300)));
            let uuid = uuid::Uuid::parse_str(&jti)?;
            assert_eq!(uuid.get_version_num(), 4);
            assert_eq!(uuid.to_string(), jti);
            if let Some(token) = claims
                .get("accessToken")
                .and_then(Value::as_str)
                .filter(|token| *token != "user-b")
            {
                let _ = tokens.insert(token.to_owned());
            }
            let mut expected = if scenario.branch == "existing" {
                let seed = rows(before, "account")?
                    .iter()
                    .find(|row| row["id"] == "account-a")
                    .ok_or("Seeded Account missing")?;
                values::revive(seed)?
                    .json()?
                    .ok_or("Seeded Account JSON missing")?
            } else {
                values::revive(hook(events, "account", "after").ok_or("Created Account missing")?)?
                    .json()?
                    .ok_or("Created Account JSON missing")?
            };
            if scenario.branch == "existing" && scenario.mode != "update-disabled" {
                expected["providerId"] = json!("google");
                expected["idToken"] = json!(ID_TOKEN);
                expected["accessToken"] = claims
                    .get("accessToken")
                    .cloned()
                    .ok_or("Cookie access token missing")?;
            }
            assert_eq!(
                Value::Object(claims.clone()),
                expected,
                "Cookie must contain the complete selected Account record"
            );
            anchors.account_cookies.push(json!({"keys": keys, "account": claims, "iat": "<cookie.iat>", "exp": "<cookie.exp>", "jti": "<cookie.jti>"}));
            let _ = anchors.replacements.insert(cookie.clone(), "better-auth.account_data=<verified-account-cookie>; Max-Age=300; Path=/; HttpOnly; SameSite=Lax".into());
        }
        for token in &tokens {
            let plaintext = better_auth_core::utils::symmetric::decrypt(SECRET, token)?;
            assert_eq!(
                plaintext,
                if scenario.callback {
                    "callback-access"
                } else {
                    "fresh-access"
                }
            );
            assert_ne!(token, &plaintext);
            let _ = anchors
                .replacements
                .insert(token.clone(), "<encrypted-access-token>".into());
        }
        assert!(
            tokens.len() <= 1,
            "Cookie and Account write must retain the same encrypted token, without a second encryption"
        );
        anchors.encrypted_token = !tokens.is_empty();
        assert_eq!(
            response
                .cookies
                .iter()
                .filter(|cookie| cookie.starts_with("better-auth.session_token="))
                .count(),
            usize::from(complete.is_some())
        );
        for cookie in cookies
            .iter()
            .filter(|cookie| cookie.starts_with("better-auth.session_token="))
        {
            let (pair, attributes) = cookie
                .split_once(';')
                .ok_or("Session Cookie attributes missing")?;
            let signed = pair
                .strip_prefix("better-auth.session_token=")
                .ok_or("Session Cookie prefix missing")?;
            let token = better_auth_core::utils::cookie_utils::verify_cookie_value(signed, SECRET)
                .ok_or("Session Cookie signature invalid")?;
            assert_eq!(Some(token.as_str()), anchors.token.as_deref());
            assert_eq!(attributes, " Max-Age=3600; Path=/; HttpOnly; SameSite=Lax");
            let _ = anchors.replacements.insert(
                cookie.clone(),
                format!("better-auth.session_token=<verified-signed-session-token>;{attributes}"),
            );
        }
        for event in events
            .iter()
            .filter(|event| event["kind"] == "hook-headers" && event["model"] == "account")
        {
            assert_eq!(
                event["cookies"]
                    .as_array()
                    .ok_or("Hook Cookies missing")?
                    .iter()
                    .any(|cookie| cookie
                        .as_str()
                        .is_some_and(|cookie| cookie.starts_with("better-auth.account_data="))),
                scenario.branch == "existing"
            );
        }
        if scenario.callback {
            assert_eq!(
                response.cookies.first().map(String::as_str),
                Some("better-auth.oauth_state=; Max-Age=0; Path=/; HttpOnly; SameSite=Lax")
            );
            assert!(
                response
                    .cookies
                    .get(1)
                    .is_some_and(|cookie| cookie.starts_with("better-auth.account_data="))
            );
        }
        let mut observations = std::mem::take(&mut anchors.account_cookies);
        for observation in &mut observations {
            anchors.normalize_record("account", &mut observation["account"])?;
        }
        anchors.account_cookies = observations;
        Ok(anchors)
    }

    fn normalize_text(&self, text: &mut String) {
        let mut replacements: Vec<_> = self.replacements.iter().collect();
        replacements.sort_by_key(|(from, _)| std::cmp::Reverse(from.len()));
        for (from, to) in replacements {
            *text = text.replace(from, to);
        }
    }

    fn normalize(&self, value: &mut Value) {
        match value {
            Value::String(text) => self.normalize_text(text),
            Value::Array(values) => values.iter_mut().for_each(|value| self.normalize(value)),
            Value::Object(values) => values.values_mut().for_each(|value| self.normalize(value)),
            _ => {}
        }
    }

    fn normalize_record(&self, model: &str, row: &mut Value) -> TestResult {
        if let Some(fields) = row.as_object_mut() {
            for field in ["createdAt", "updatedAt", "expiresAt"] {
                if let (Some(instant), Some(value)) = (
                    self.dates.get(&format!("{model}.{field}")),
                    fields.get_mut(field),
                ) {
                    if value.is_null() || value["type"] == "undefined" {
                        continue;
                    }
                    if millis(value)? == *instant {
                        let label = format!("<{model}.{field}>");
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

    pub(super) fn normalize_events(&self, events: &mut [Value], scenario: &Scenario) -> TestResult {
        for event in events {
            if event["kind"] == "hook" {
                let model = text(event, "model")?.to_owned();
                self.normalize_record(&model, &mut event["data"])?;
            } else if event["kind"] == "admission" && scenario.branch == "new" {
                self.normalize_record("user", &mut event["data"]["user"])?;
            }
            self.normalize(event);
        }
        Ok(())
    }

    pub(super) fn normalize_storage(&self, snapshot: &mut Value) -> TestResult {
        for model in ["user", "account", "session"] {
            for row in snapshot[model]
                .as_array_mut()
                .ok_or("Snapshot table missing")?
            {
                self.normalize_record(model, row)?;
            }
        }
        Ok(())
    }

    pub(super) fn normalize_response(&self, response: &mut http::Response) -> TestResult {
        for [_, value] in &mut response.headers {
            self.normalize_text(value);
        }
        for cookie in &mut response.cookies {
            self.normalize_text(cookie);
        }
        if !response.body.is_empty() {
            let mut body: Value = serde_json::from_str(&response.body)?;
            if let Some(user) = body.get_mut("user") {
                self.normalize_record("user", user)?;
            }
            self.normalize(&mut body);
            response.body = serde_json::to_string(&body)?;
        }
        Ok(())
    }
}

pub(super) fn assert_events(actual: &[Value], case: &Case, scenario: &Scenario) -> TestResult {
    let console: Vec<_> = case
        .events
        .iter()
        .filter(|event| event["kind"] == "console.error")
        .cloned()
        .collect();
    if scenario.branch == "existing" && scenario.mode == "cookie-failure" {
        assert_eq!(
            console,
            vec![
                json!({"kind": "console.error", "args": ["# SERVER_ERROR: ", {"name": "Error", "message": COOKIE_FAILURE, "properties": {}, "keys": []}]})
            ]
        );
        assert!(actual.iter().any(|event| event == &json!({"kind": "api-error", "error": {"name": "Error", "message": COOKIE_FAILURE}})));
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
    assert_eq!(
        actual, expected,
        "{case:?}: full ordered callbacks, field keys, query spans, and Cookie visibility"
    );
    Ok(())
}
