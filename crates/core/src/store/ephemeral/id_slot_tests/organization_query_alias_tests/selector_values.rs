use super::*;

#[tokio::test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "The source contract compares native identities, complete records, callbacks, and transaction persistence."
)]
async fn selector_values_retain_claim_output_and_adapter_transaction_identity() -> AuthResult<()> {
    let fixture: JsonValue = serde_json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../tests/fixtures/invitation-claim-selector-values-1.7.6.json"
    )))?;
    assert_eq!(required(fixture.get("version"))?, "1.7.6");
    assert_eq!(required(fixture.get("backend"))?, "memory");
    let cases = required(required(fixture.get("cases"))?.as_array())?;
    assert_eq!(
        cases
            .iter()
            .map(|case| required(case.get("scenario")).cloned())
            .collect::<AuthResult<Vec<_>>>()?,
        [
            "invitation-own-selector-id-nan",
            "invitation-own-selector-id-object",
            "invitation-own-selector-lookup-nan",
            "invitation-own-selector-lookup-object",
        ]
        .map(JsonValue::from),
    );
    for case in cases {
        let scenario = required(case.get("scenario"))?;
        let column = required(required(case.get("column"))?.as_str())?;
        let replacement = match required(required(case.get("kind"))?.as_str())? {
            "nan" => Value::Number(f64::NAN),
            "object" => FieldMap::from([
                ("marker".into(), "claimed-object".into()),
                ("ownUndefined".into(), Value::Undefined),
            ])
            .into(),
            _ => return Err(AuthError::internal("Unknown selector value source case")),
        };
        let trace = Events::default();
        let update_trace = trace.clone();
        let update_value = replacement.clone();
        let mut fields = OrganizationFields::default();
        let mapped = UserFieldConfig {
            field_name: Some(column.into()),
            ..Default::default()
        };
        let _ = fields
            .invitation
            .fields_mut()
            .insert("id".into(), mapped.clone());
        let _ = fields.invitation.fields_mut().insert(
            "claimLookup".into(),
            UserFieldConfig {
                on_update: Some(crate::user_fields::UserFieldFactory::new(move || {
                    record(
                        &update_trace,
                        json!([
                            "onUpdate",
                            "invitation.claimLookup",
                            value_observation(&update_value)?
                        ]),
                    )?;
                    Ok(update_value.clone())
                })),
                ..mapped
            },
        );
        let store = EphemeralStore::new(Arc::new(AuthConfig::default()));
        store.configure_organization_fields(fields)?;
        let steps = required(required(case.get("steps"))?.as_array())?;
        assert_eq!(steps.len(), 2);
        let first = required(steps.first())?;
        seed(&store, required(first.get("before"))?)?;
        let original = store.operation(|operation| {
            required(operation.capture_table(EntityRole::Invitation)?.row_at(0)?)
        })?;
        let before = memory(&store)?;
        // The direct Rust helper has no fromStatus argument. Aggregate acceptance covers the pending predicate.
        assert_eq!(
            required(first.get("input"))?,
            &json!({"invitationId":"invitation-alias", "status":"accepted", "fromStatus":"pending"})
        );
        let returned: Value = required(
            store
                .update_invitation_status_value(
                    &"invitation-alias".into(),
                    InvitationStatus::Accepted,
                )
                .await?,
        )?
        .field_values()?
        .into();
        let returned_lookup = returned.model_property("claimLookup")?;
        for (index, result) in [(0, returned), (1, true.into())] {
            let step = required(steps.get(index))?;
            let before = if index == 0 {
                before.clone()
            } else {
                let before = memory(&store)?;
                assert_eq!(
                    required(step.get("input"))?,
                    &json!({"operation":"read-only-adapter-transaction"})
                );
                let committed =
                    crate::store::transaction(&store, |_| Box::pin(async { Ok(true) })).await?;
                assert!(committed);
                before
            };
            let rows = store.operation(|operation| {
                operation
                    .capture_table(EntityRole::Invitation)?
                    .snapshot_refs()
            })?;
            let identities = json!({
                "originalRows":rows.iter().map(|row| row.same_row(&original)).collect::<Vec<_>>(),
                "originalValues":rows.iter().map(|row| Ok(required(row.field(column)?)?.same_value_zero(&replacement))).collect::<AuthResult<Vec<_>>>()?,
                "returnedLookupIsReplacement":returned_lookup.same_value_zero(&replacement),
            });
            let observed = json!({
                "before":before, "returned":true, "result":value_observation(&result)?,
                "keyOrder":key_order(&result, Vec::new())?,
                "events":std::mem::take(&mut *trace.lock().map_err(|_| AuthError::internal("Selector value event lock poisoned"))?),
                "after":memory(&store)?, "identities":identities,
            });
            for key in [
                "before",
                "returned",
                "result",
                "keyOrder",
                "events",
                "after",
                "identities",
            ] {
                assert_eq!(
                    required(step.get(key))?,
                    required(observed.get(key))?,
                    "{}/{index}/{key}",
                    scenario
                );
            }
        }
    }
    Ok(())
}
