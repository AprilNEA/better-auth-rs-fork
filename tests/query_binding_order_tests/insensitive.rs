use better_auth_core::{
    AuthConfig, AuthError, AuthRecordFields, DeviceCodeOwnership, DeviceCodeWhere, FieldValue,
    WhereMode, WhereOperator, store::DeviceCodeStore,
};
use better_auth_seaorm::{
    SeaOrmStore,
    sea_orm::{ConnectOptions, ConnectionTrait, Database, EntityTrait, QueryOrder, Schema},
    store::{__private_test_support::bundled_schema::BundledSchema, entities::device_code},
};

#[tokio::test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "Assertions compare consumed rows, errors, and storage; Result propagates database and adapter errors"
)]
async fn sqlite_device_insensitive_ownership_distinguishes_scalar_and_array_operands()
-> Result<(), Box<dyn std::error::Error>> {
    for operator in [
        WhereOperator::Eq,
        WhereOperator::Ne,
        WhereOperator::In,
        WhereOperator::NotIn,
        WhereOperator::Contains,
        WhereOperator::StartsWith,
        WhereOperator::EndsWith,
    ] {
        for array in [false, true] {
            let mut options = ConnectOptions::new("sqlite::memory:");
            let _ = options.max_connections(1);
            let database = Database::connect(options).await?;
            let _ = database
                .execute(
                    &Schema::new(database.get_database_backend())
                        .create_table_from_entity(device_code::Entity),
                )
                .await?;
            // SQLite's default LIKE hides whether the adapter selected an insensitive expression.
            let _ = database
                .execute_unprepared("PRAGMA case_sensitive_like = ON")
                .await?;
            let _ = database.execute_unprepared(
                "INSERT INTO device_code (id, device_code, user_code, user_id, expires_at, status, client_id, scope) \
                 VALUES ('target', 'target-device', 'ABCD2345', 'owner', '2030-01-01T00:00:00.000Z', 'approved', 'client', 'upper'), \
                 ('retained', 'retained-device', 'EFGH2345', 'owner', '2030-01-01T00:00:00.000Z', 'approved', 'client', 'upper')",
            ).await?;
            let before = device_code::Entity::find()
                .order_by_asc(device_code::Column::Id)
                .all(&database)
                .await?;
            assert_eq!(before.len(), 2);
            let store = SeaOrmStore::<BundledSchema>::new(AuthConfig::default(), database.clone());
            let target = store
                .get_device_code_by_device_code("target-device")
                .await?
                .ok_or_else(|| AuthError::internal("Seed Device code is missing"))?;
            let value = if array {
                FieldValue::from(vec![FieldValue::from("UPPER")])
            } else {
                "UPPER".into()
            };
            let consumed = store
                .consume_device_code(
                    &target,
                    &DeviceCodeOwnership::Where(DeviceCodeWhere {
                        field: "scope".into(),
                        operator,
                        value,
                        mode: WhereMode::Insensitive,
                    }),
                )
                .await;
            if operator == WhereOperator::In && !array {
                assert!(
                    matches!(consumed, Err(AuthError::Config(message)) if message == "Value must be an array")
                );
                assert_eq!(
                    device_code::Entity::find()
                        .order_by_asc(device_code::Column::Id)
                        .all(&database)
                        .await?,
                    before
                );
                continue;
            }
            let consumed = consumed?;
            let consumes = match operator {
                WhereOperator::In => true,
                WhereOperator::NotIn => false,
                WhereOperator::Ne => array,
                _ => !array,
            };
            assert_eq!(
                consumed
                    .as_ref()
                    .map(AuthRecordFields::field_values)
                    .transpose()?,
                consumes.then(|| target.field_values()).transpose()?,
                "{operator:?}, array={array}"
            );
            let expected = before
                .into_iter()
                .filter(|row| !consumes || row.id != "target")
                .collect::<Vec<_>>();
            assert_eq!(
                device_code::Entity::find()
                    .order_by_asc(device_code::Column::Id)
                    .all(&database)
                    .await?,
                expected,
                "{operator:?}, array={array}"
            );
        }
    }
    Ok(())
}
