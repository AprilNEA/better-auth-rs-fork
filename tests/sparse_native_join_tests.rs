#![cfg(feature = "seaorm2")]
#![expect(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "The paired contract requires complete static case shapes and fails on malformed cases"
)]

#[path = "support/sparse_native_join_contract.rs"]
mod contract;
#[path = "support/sparse_native_join_models.rs"]
mod models;
#[path = "support/device_where_values.rs"]
mod values;

use better_auth_core::{AuthError, ListUsersParams};
use serde_json::Value;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

#[tokio::test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "Assertions compare counts, callbacks, and storage; Result propagates fixture and adapter errors"
)]
async fn adapter_counts_exclude_null_ids_without_projecting_or_mutating_records() -> TestResult {
    let cases: Value =
        serde_json::from_str(include_str!("fixtures/sparse-native-join-cases.json"))?;
    for query in cases["adapterCounts"].as_array().unwrap() {
        let mut input = cases.clone();
        let table = input["tables"]
            .as_array_mut()
            .unwrap()
            .iter_mut()
            .find(|table| table["model"] == query["model"])
            .unwrap();
        table["columns"]["id"] = "TEXT".into();
        let rows = table["rows"].as_array_mut().unwrap();
        let mut null_id = rows[0].clone();
        null_id["id"] = Value::Null;
        let mut excluded = rows[0].clone();
        excluded["id"] = "excluded".into();
        excluded[query["column"].as_str().unwrap()] = "another-owner".into();
        rows.extend([null_id, excluded]);
        let fixture = contract::Fixture::new(&input, &input["cases"][0], false, false).await?;
        let before = fixture.snapshot().await?;
        let value = values::revive(&query["value"])?;
        contract::assert_value(
            &fixture
                .count(query["model"].as_str().unwrap(), &value)
                .await?,
            &query["total"],
        )?;
        assert!(fixture.events.lock().unwrap().is_empty());
        assert_eq!(fixture.snapshot().await?, before);
        if query["model"] == "apikey" {
            contract::assert_value(
                &fixture.read_api_keys(&value).await?,
                &cases["nullableApiKey"]["result"],
            )?;
            assert_eq!(
                *fixture.events.lock().unwrap(),
                *cases["nullableApiKey"]["events"].as_array().unwrap()
            );
            assert_eq!(fixture.snapshot().await?, before);
        }
    }
    Ok(())
}

#[tokio::test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "Assertions compare page counts, callbacks, and storage; Result propagates fixture and adapter errors"
)]
async fn nullable_user_ids_remain_in_pages_but_do_not_contribute_to_sql_counts() -> TestResult {
    let cases: Value =
        serde_json::from_str(include_str!("fixtures/sparse-native-join-cases.json"))?;
    let mut input = cases.clone();
    let user = &cases["nullableUser"];
    let table = input["tables"]
        .as_array_mut()
        .unwrap()
        .iter_mut()
        .find(|table| table["model"] == "user")
        .unwrap();
    table["columns"]["id"] = "TEXT".into();
    table["rows"]
        .as_array_mut()
        .unwrap()
        .push(user["row"].clone());
    let fixture = contract::Fixture::new(&input, &input["cases"][0], false, false).await?;
    let before = fixture.snapshot().await?;
    for query in user["queries"].as_array().unwrap() {
        fixture.events.lock().unwrap().clear();
        let filter = query.get("filter");
        let params = ListUsersParams {
            limit: query["limit"].as_f64(),
            offset: query["offset"].as_f64(),
            sort_by: Some("name".into()),
            sort_direction: Some("asc".into()),
            filter_field: filter.map(|filter| filter["field"].as_str().unwrap().into()),
            filter_operator: filter.map(|filter| filter["operator"].as_str().unwrap().into()),
            filter_value: filter
                .map(|filter| values::revive(&filter["value"]))
                .transpose()?,
            ..Default::default()
        };
        contract::assert_value(
            &fixture.read_users(params).await?,
            &serde_json::json!({"users": [user["result"]], "total": query["total"]}),
        )?;
        assert_eq!(
            *fixture.events.lock().unwrap(),
            *user["events"].as_array().unwrap()
        );
        assert_eq!(fixture.snapshot().await?, before);
    }
    Ok(())
}

#[tokio::test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "Assertions compare errors, callbacks, and storage; Result propagates fixture and adapter errors"
)]
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
#[expect(
    clippy::panic_in_result_fn,
    reason = "Assertions compare database errors, callback order, and storage; Result propagates fixture errors"
)]
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
#[expect(
    clippy::panic_in_result_fn,
    reason = "Assertions compare child callbacks and storage; Result propagates fixture and adapter errors"
)]
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

#[tokio::test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "Assertions compare duplicate child callbacks and storage; Result propagates fixture and adapter errors"
)]
async fn zero_child_ids_are_not_deduplicated_before_id_output_conversion() -> TestResult {
    let cases: Value =
        serde_json::from_str(include_str!("fixtures/sparse-native-join-cases.json"))?;
    for joins in [false, true] {
        let mut input = cases.clone();
        let table = input["tables"]
            .as_array_mut()
            .unwrap()
            .iter_mut()
            .find(|table| table["model"] == "teamMember")
            .unwrap();
        table["columns"]["id"] = "INTEGER".into();
        table["rows"] = cases["zeroChildRows"].clone();
        let case = &input["cases"][0];
        let fixture = contract::Fixture::new(&input, case, joins, false).await?;
        let before = fixture.snapshot().await?;
        let mut expected = case["result"].clone();
        expected["members"] = serde_json::json!([
            {"teamId": "team", "id": "0"}, {"teamId": "team", "id": "0"}
        ]);
        contract::assert_value(&fixture.read("team").await?, &expected)?;
        let mut events = case["events"].as_array().unwrap().clone();
        events.push(case["events"][2].clone());
        assert_eq!(*fixture.events.lock().unwrap(), events);
        assert_eq!(fixture.snapshot().await?, before);
    }
    Ok(())
}

#[tokio::test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "Assertions compare row presence, callbacks, and storage; Result propagates fixture and adapter errors"
)]
async fn native_joins_discard_falsy_parent_ids_before_any_output_callbacks() -> TestResult {
    let cases: Value =
        serde_json::from_str(include_str!("fixtures/sparse-native-join-cases.json"))?;
    for joins in [false, true] {
        for case in cases["falsyParentCases"].as_array().unwrap() {
            let mut input = cases.clone();
            let table = input["tables"]
                .as_array_mut()
                .unwrap()
                .iter_mut()
                .find(|table| table["model"] == case["model"])
                .unwrap();
            table["columns"]["id"] = case["idType"].clone();
            table["rows"][0]["id"] = case["id"].clone();
            let fixture = contract::Fixture::new(&input, case, joins, false).await?;
            let before = fixture.snapshot().await?;
            let selector = values::revive(&case["id"])?;
            let result = fixture
                .read_selected(case["path"].as_str().unwrap(), &selector)
                .await?;
            if joins {
                assert!(result.is_none());
                assert!(fixture.events.lock().unwrap().is_empty());
            } else {
                contract::assert_value(&result.unwrap(), &case["result"])?;
                assert_eq!(
                    *fixture.events.lock().unwrap(),
                    *case["events"].as_array().unwrap()
                );
            }
            assert_eq!(fixture.snapshot().await?, before);
        }
    }
    Ok(())
}

#[tokio::test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "Assertions compare alias callbacks and storage; Result propagates fixture and adapter errors"
)]
async fn reserved_child_aliases_remove_parent_fields_without_losing_own_undefined() -> TestResult {
    let cases: Value =
        serde_json::from_str(include_str!("fixtures/sparse-native-join-cases.json"))?;
    let collision = &cases["aliasCollision"];
    for key in ["column", "alternateColumn"] {
        let column = collision[key].as_str().unwrap();
        for joins in [false, true] {
            for populated in [false, true] {
                let mut input = cases.clone();
                for table in input["tables"].as_array_mut().unwrap() {
                    if table["model"] == "team" {
                        table["columns"][column] = "TEXT".into();
                        table["rows"][0][column] = collision["value"].clone();
                    } else if table["model"] == "teamMember" && !populated {
                        table["rows"] = serde_json::json!([]);
                    }
                }
                input["declarations"]["team"]["shadow"] = serde_json::json!({"fieldName": column});
                let fixture =
                    contract::Fixture::new(&input, &input["cases"][0], joins, false).await?;
                let before = fixture.snapshot().await?;
                let (result, events) = if joins {
                    ("nativeResult", "nativeEvents")
                } else {
                    ("fallbackResult", "fallbackEvents")
                };
                let mut expected = collision[result].clone();
                let mut events = collision[events].as_array().unwrap().clone();
                if !populated {
                    expected["members"] = serde_json::json!([]);
                    let _ = events.pop();
                }
                contract::assert_value(&fixture.read("team").await?, &expected)?;
                assert_eq!(*fixture.events.lock().unwrap(), events);
                assert_eq!(fixture.snapshot().await?, before);
            }
        }
    }
    Ok(())
}
