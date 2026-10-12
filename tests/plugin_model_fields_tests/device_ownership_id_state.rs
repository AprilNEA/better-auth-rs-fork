use super::*;

#[tokio::test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "The transaction must consume through the first physical ID alias and reject a later change to that selected field"
)]
async fn memory_device_first_id_alias_change_conflicts_before_commit() -> AuthResult<()> {
    let mut policies = ownership_fields();
    for (name, column) in [("id", "old_id"), ("selectionId", "old_id")] {
        let _ = policies.fields_mut().insert(
            name.into(),
            UserFieldConfig {
                field_name: Some(column.into()),
                required: Some(false),
                ..Default::default()
            },
        );
    }
    let (auth, observation) = setup(memory(), policies).await?;
    let selected = auth
        .store()
        .update_device_code(
            &observation.seeded.id,
            UpdateDeviceCode {
                additional_fields: [("selectionId".into(), observation.seeded.id.field_value())]
                    .into(),
                ..Default::default()
            },
        )
        .await?;
    let expected = selected.clone();
    let external_store = auth.store().clone();
    let result = transaction(auth.store().as_ref(), move |transaction| {
        Box::pin(async move {
            assert_eq!(
                transaction
                    .consume_device_code(
                        &selected,
                        &DeviceCodeOwnership::FieldEquals {
                            field: "tenantKey".into(),
                            value: "tenant-before".into(),
                        },
                    )
                    .await?,
                Some(selected.clone())
            );
            external_store
                .update_device_code(
                    &selected.id,
                    UpdateDeviceCode {
                        additional_fields: [("selectionId".into(), "external-id".into())].into(),
                        ..Default::default()
                    },
                )
                .await
        })
    })
    .await;
    original_error(
        result
            .err()
            .ok_or_else(|| AuthError::internal("The selected ID change must reject commit"))?,
        "Device code changed before transaction commit",
    );
    let mut expected = expected;
    let _ = expected
        .additional_fields
        .insert("selectionId".into(), "external-id".into());
    assert_eq!(
        auth.store()
            .get_device_code_by_device_code(expected.device_code.typed()?)
            .await?,
        Some(expected)
    );
    Ok(())
}
