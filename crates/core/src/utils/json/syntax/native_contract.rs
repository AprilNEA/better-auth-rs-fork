use crate::{AuthError, AuthResult, FieldValue, Utf16String};
use serde::Deserialize;
use serde_json::{Value as Json, json, value::RawValue};

#[path = "../../../../../../tests/support/secondary_native_observation.rs"]
mod observation;

#[derive(Deserialize)]
struct Fixture<'a> {
    version: String,
    #[serde(borrow)]
    cases: Vec<&'a RawValue>,
}

#[derive(Deserialize)]
struct Case<'a> {
    name: String,
    category: String,
    mode: String,
    input: Json,
    #[serde(borrow)]
    runtime: &'a RawValue,
}

#[derive(Deserialize)]
struct Runtime {
    outcome: Outcome,
}

#[derive(Deserialize)]
struct Outcome {
    returned: bool,
}

fn input(value: Json) -> AuthResult<FieldValue> {
    if let Json::String(value) = value {
        return Ok(value.into());
    }
    if value.get("type").and_then(Json::as_str) == Some("utf16") {
        let units: Vec<u16> = serde_json::from_value(
            value
                .get("value")
                .cloned()
                .ok_or_else(|| AuthError::internal("Missing UTF-16 source units"))?,
        )?;
        return Ok(Utf16String::from_units(units).into());
    }
    Err(AuthError::internal("Expected native JSON source text"))
}

#[test]
fn source_parser_diagnostics_match_complete_runtime_observations() -> AuthResult<()> {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/json-parse-native-1.7.6.json");
    let source = std::fs::read_to_string(path).map_err(|error| {
        AuthError::internal(format!(
            "Cannot read JSON parser source observations: {error}"
        ))
    })?;
    let fixture: Fixture<'_> = serde_json::from_str(&source)?;
    assert_eq!(fixture.version, "1.7.6");
    let mut count = 0;
    for case in fixture.cases {
        let case: Case<'_> = serde_json::from_str(case.get())?;
        if case.category == "coercion" || case.mode != "direct" {
            continue;
        }
        let runtime: Runtime = serde_json::from_str(case.runtime.get())?;
        if runtime.outcome.returned {
            continue;
        }
        let error = crate::utils::json::parse_native_json(&input(case.input)?)
            .err()
            .ok_or_else(|| AuthError::internal(format!("{} unexpectedly parsed", case.name)))?;
        let thrown = error.into_thrown_value()?;
        let mut observer = observation::NativeObservation::default();
        let message = thrown.own_property_descriptor("message")?;
        let details = json!({
            "name": observer.observe(&thrown.model_property("name")?)?,
            "message": observer.observe(&thrown.model_property("message")?)?,
            "display": observer.observe(&thrown.display_utf16()?.into())?,
            "hasOwnMessage": message.is_some(),
            "messageEnumerable": message.map(|descriptor| descriptor.enumerable),
            "hasOwnName": thrown.own_property_descriptor("name")?.is_some(),
            "enumerable": observer.observe(&thrown)?,
        });
        let outcome =
            observer.outcome(Err(AuthError::from_thrown(thrown)), &FieldValue::Undefined)?;
        let actual = json!({
            "outcome": outcome,
            "error": details,
            "events": [],
            "reviverKeys": [],
            "sameInput": false,
            "mutation": {"type":"undefined"},
            "functionIds": observer.function_ids(),
        });
        let expected: Json = serde_json::from_str(case.runtime.get())?;
        observation::assert_replay(&actual, &expected, &case.name);
        count += 1;
    }
    assert_eq!(count, 114);
    Ok(())
}
