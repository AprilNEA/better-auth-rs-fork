#![cfg(feature = "seaorm2")]
#![expect(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "The paired contract requires complete static case shapes and fails on malformed cases"
)]

#[path = "support/sparse_native_join_contract.rs"]
mod contract;

use better_auth_core::AuthError;
use serde_json::Value;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

#[tokio::test]
async fn sparse_native_and_fallback_joins_match_complete_results_callbacks_and_storage()
-> TestResult {
    let cases: Value =
        serde_json::from_str(include_str!("fixtures/sparse-native-join-cases.json"))?;
    for joins in [false, true] {
        for case in cases["cases"].as_array().unwrap() {
            for reject in [false, true] {
                let fixture = contract::Fixture::new(&cases, case, joins, reject).await?;
                let before = fixture.snapshot().await?;
                assert!(fixture.events.lock().unwrap().is_empty());
                let result = fixture.read(case["path"].as_str().unwrap()).await;
                let mut expected_events = Vec::new();
                for event in case["events"].as_array().unwrap() {
                    expected_events.push(event.clone());
                    if reject && event[0] == case["rejectAt"] {
                        break;
                    }
                }
                if reject {
                    assert_eq!(
                        result.unwrap_err().instrumentation_message(),
                        "sparse-native-output-rejected"
                    );
                } else {
                    contract::assert_value(&result?, &case["result"])?;
                }
                assert_eq!(*fixture.events.lock().unwrap(), expected_events);
                assert_eq!(fixture.snapshot().await?, before);
            }
        }
    }
    Ok(())
}

#[tokio::test]
async fn missing_declared_child_columns_keep_native_and_fallback_error_order() -> TestResult {
    use better_auth_seaorm::sea_orm::ConnectionTrait;

    let cases: Value =
        serde_json::from_str(include_str!("fixtures/sparse-native-join-cases.json"))?;
    let case = &cases["cases"][0];
    for joins in [false, true] {
        let fixture = contract::Fixture::new(&cases, case, joins, false).await?;
        let _ = fixture
            .database
            .execute_unprepared("ALTER TABLE team_member DROP COLUMN team_id")
            .await?;
        let before = fixture.snapshot().await?;
        let result = fixture.read("team").await;
        assert!(matches!(result, Err(AuthError::Database(_))));
        let expected = if joins {
            Vec::new()
        } else {
            case["events"].as_array().unwrap()[..2].to_vec()
        };
        assert_eq!(*fixture.events.lock().unwrap(), expected);
        assert_eq!(fixture.snapshot().await?, before);
    }
    Ok(())
}

#[tokio::test]
async fn null_child_ids_preserve_present_rows_and_empty_relationships() -> TestResult {
    let cases: Value =
        serde_json::from_str(include_str!("fixtures/sparse-native-join-cases.json"))?;
    for joins in [false, true] {
        for populated in [false, true] {
            let mut input = cases.clone();
            let rows = if populated {
                cases["nullableChildRows"].clone()
            } else {
                serde_json::json!([])
            };
            let table = input["tables"]
                .as_array_mut()
                .unwrap()
                .iter_mut()
                .find(|table| table["model"] == "teamMember")
                .unwrap();
            table["columns"]["id"] = "TEXT".into();
            table["rows"] = rows.clone();
            let case = &input["cases"][0];
            let fixture = contract::Fixture::new(&input, case, joins, false).await?;
            let before = fixture.snapshot().await?;
            let mut expected = case["result"].clone();
            expected["members"] = Value::Array(
                rows.as_array()
                    .unwrap()
                    .iter()
                    .map(|row| serde_json::json!({"teamId": row["team_id"], "id": row["id"]}))
                    .collect(),
            );
            contract::assert_value(&fixture.read("team").await?, &expected)?;
            let mut events = case["events"].as_array().unwrap()[..2].to_vec();
            events.extend(
                rows.as_array()
                    .unwrap()
                    .iter()
                    .map(|_| case["events"][2].clone()),
            );
            assert_eq!(*fixture.events.lock().unwrap(), events);
            assert_eq!(fixture.snapshot().await?, before);
        }
    }
    Ok(())
}
