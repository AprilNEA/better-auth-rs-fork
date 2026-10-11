#![expect(
    clippy::panic_in_result_fn,
    reason = "Contract assertions must fail the test while setup errors propagate through Result."
)]

use super::*;

pub(super) fn key_order(value: &FieldValue) -> AuthResult<Value> {
    fn visit(value: &FieldValue, path: &[String], output: &mut Vec<Value>) -> AuthResult<()> {
        let fields = if let Some(object) = value.as_object() {
            object.snapshot_fields()?.into_iter().collect::<Vec<_>>()
        } else if let Some(array) = value.as_array() {
            array
                .iter()
                .enumerate()
                .map(|(index, value)| (index.to_string(), value.clone()))
                .collect()
        } else {
            return Ok(());
        };
        output.push(
            json!({"path": path, "keys": fields.iter().map(|(key, _)| key).collect::<Vec<_>>()}),
        );
        for (key, child) in fields {
            let mut child_path = path.to_vec();
            child_path.push(key);
            visit(&child, &child_path, output)?;
        }
        Ok(())
    }

    let mut output = Vec::new();
    visit(value, &[], &mut output)?;
    Ok(output.into())
}

#[tokio::test]
async fn explicit_native_declarations_preserve_logical_and_aliased_account_owner_reads()
-> TestResult {
    let fixture: Value = serde_json::from_str(include_str!(
        "../fixtures/custom-model-join-reference-1.7.6.json"
    ))?;
    assert_eq!(fixture.get("version"), Some(&json!("1.7.6")));
    let cases = fixture
        .get("cases")
        .and_then(Value::as_array)
        .ok_or("Missing captured cases")?
        .iter()
        .filter(|case| case["scenario"] == "declared-badge-reference")
        .collect::<Vec<_>>();
    assert_eq!(cases.len(), 4);
    for (model, alias) in [("passkey", "key_store"), ("rateLimit", "counter_store")] {
        for reference in [model, alias] {
            let reference_kind = if reference == model {
                "logical"
            } else {
                "alias"
            };
            let scenario = json!({
                "name": format!("declared-{model}-{reference_kind}"),
                "declared": true, "model": model, "alias": alias, "reference": reference,
            });
            for case in &cases {
                let baseline = config(None, false, None);
                match case["backend"].as_str() {
                    Some("memory") => {
                        contract(
                            Arc::new(EphemeralStore::new(Arc::new(baseline))),
                            None,
                            &scenario,
                            case,
                        )
                        .await?;
                    }
                    Some("sqlite") => {
                        let database = storage::sqlite().await?;
                        contract(
                            Arc::new(
                                SeaOrmStore::<models::Core>::new(baseline, database.clone())
                                    .with_plugin_schema::<models::NativePlugins>(),
                            ),
                            Some(&database),
                            &scenario,
                            case,
                        )
                        .await?;
                    }
                    value => return Err(format!("Unknown backend: {value:?}").into()),
                }
            }
        }
    }
    Ok(())
}
