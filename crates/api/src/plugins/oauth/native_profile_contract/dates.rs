use super::*;

const RECORD_DATES: &[&str] = &["createdAt", "updatedAt"];
const TOKEN_DATES: &[&str] = &["accessTokenExpiresAt", "refreshTokenExpiresAt"];

fn replace(value: &mut Value, dates: &HashMap<String, String>) {
    let value = if value.get("type").is_some_and(|kind| kind == "date") {
        &mut value["value"]
    } else {
        value
    };
    if let Some(replacement) = value.as_str().and_then(|value| dates.get(value)) {
        *value = Value::String(replacement.clone());
    }
}

fn record(value: &mut Value, names: &[&str], dates: &HashMap<String, String>) {
    for name in names {
        if let Some(value) = value.get_mut(*name) {
            replace(value, dates);
        }
    }
}

fn model(value: &mut Value, name: &str, dates: &HashMap<String, String>) {
    record(value, RECORD_DATES, dates);
    match name {
        "session" => record(value, &["expiresAt"], dates),
        "account" => record(value, TOKEN_DATES, dates),
        _ => {}
    }
}

pub(super) fn apply(
    events: &mut [Value],
    after: &mut Value,
    scenario: &Scenario,
    dates: &HashMap<String, String>,
) {
    for event in events {
        match event["kind"].as_str().unwrap() {
            "get-user-info" | "subject" | "generic-subject" => {
                if let Some(tokens) = event.get_mut("tokens") {
                    record(tokens, TOKEN_DATES, dates);
                }
            }
            "hook" => {
                let name = event["model"].as_str().unwrap().to_owned();
                model(&mut event["data"], &name, dates);
            }
            "admission" => record(&mut event["user"], RECORD_DATES, dates),
            _ => {}
        }
    }
    // Native observations and JSON observations expose the same generated fields at different paths.
    for pointer in ["/native/value", "/json/value/value"] {
        if scenario.operation == "direct"
            && let Some(result) = after["result"].pointer_mut(pointer)
            && let Some(user) = result.get_mut("user")
        {
            record(user, RECORD_DATES, dates);
        }
        if let Some(admissions) = after["admissions"]
            .pointer_mut(pointer)
            .and_then(Value::as_array_mut)
        {
            for admission in admissions {
                record(&mut admission["user"], RECORD_DATES, dates);
            }
        }
        if let Some(storage) = after["storage"].pointer_mut(pointer) {
            for name in ["user", "session", "account", "verification"] {
                if let Some(rows) = storage.get_mut(name).and_then(Value::as_array_mut) {
                    for row in rows {
                        model(row, name, dates);
                    }
                }
            }
        }
    }
}

#[test]
fn generated_dates_preserve_equal_provider_strings_outside_generated_fields() {
    let fixture = fixture();
    let scenario: Scenario = serde_json::from_value(
        fixture["scenarios"]
            .as_array()
            .unwrap()
            .iter()
            .find(|scenario| scenario["name"] == "social-direct-falsy-defaults")
            .unwrap()
            .clone(),
    )
    .unwrap();
    let actual = "2031-06-07T08:09:10.000Z";
    let sample = |generated: &str| {
        let profile = json!({"createdAt": actual, "name": actual, "extension": {"date": actual}});
        let record = |date: Value| {
            json!({
                "createdAt": date, "updatedAt": date, "name": actual,
                "image": {"createdAt": actual}, "profileExtra": {"date": actual},
            })
        };
        let native = record(json!({"type": "date", "value": generated}));
        let json = record(json!(generated));
        let source = json!({"oauth": {"profile": profile}});
        let events = vec![
            json!({"kind": "get-user-info", "tokens": {
                "accessTokenExpiresAt": {"type": "date", "value": generated},
                "raw": {"accessTokenExpiresAt": actual},
            }}),
            json!({"kind": "hook", "model": "user", "data": native}),
            json!({"kind": "admission", "user": native, "profile": profile}),
            json!({"kind": "descriptor", "object": "raw", "key": actual}),
        ];
        let after = json!({
            "raw": profile, "mapped": profile, "providerResponse": {"user": profile},
            "result": {
                "native": {"returned": true, "value": {"user": native}},
                "json": {"returned": true, "value": {"defined": true, "value": {"user": json}}},
                "keyOrder": [{"path": [actual], "keys": [actual]}],
            },
            "admissions": {
                "native": {"returned": true, "value": [{"user": native, "source": source}]},
                "json": {"returned": true, "value": {"defined": true, "value": [{"user": json, "source": source}]}},
            },
            "storage": {
                "native": {"returned": true, "value": {"user": [native]}},
                "json": {"returned": true, "value": {"defined": true, "value": {"user": [json]}}},
            },
        });
        (events, after)
    };
    let (mut events, mut after) = sample(actual);
    apply(
        &mut events,
        &mut after,
        &scenario,
        &HashMap::from([(actual.into(), DATE.into())]),
    );
    let (expected_events, expected_after) = sample(DATE);
    assert_eq!(events, expected_events);
    assert_eq!(after, expected_after);
}
