use super::{Trace, record, take_trace};
use better_auth_core::{
    AuthConfig, AuthError, AuthResult, FieldFunction, FieldMap, FieldValue, SchemaValue,
    store::{TwoFactorStore, UserStore, WalletStore},
    user_fields::UserFieldFactory,
};
use better_auth_seaorm::{
    SeaOrmStore,
    sea_orm::{ConnectOptions, ConnectionTrait, Database, EntityTrait, QueryOrder, Schema},
    store::{
        __private_test_support::bundled_schema::BundledSchema,
        entities::{two_factor, user, wallet_address},
    },
};
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

fn callback(trace: &Trace, allocation: &Arc<AtomicUsize>, event: &'static str) -> FieldValue {
    let trace = trace.clone();
    let allocation = allocation.clone();
    let factory: UserFieldFactory = Arc::new(move || {
        record(&trace, event)?;
        let message = format!("plugin-selector-{event}");
        allocation.store(message.as_ptr() as usize, Ordering::SeqCst);
        Err(AuthError::Internal(message))
    });
    FieldFunction::from(factory).into()
}

#[tokio::test]
async fn wallet_and_two_factor_parse_all_selector_expressions_before_driver_values()
-> Result<(), Box<dyn std::error::Error>> {
    for model in ["walletAddress", "twoFactor"] {
        for array in [false, true] {
            let mut options = ConnectOptions::new("sqlite::memory:");
            let _ = options.max_connections(1);
            let database = Database::connect(options).await?;
            let schema = Schema::new(database.get_database_backend());
            let _ = database
                .execute(&schema.create_table_from_entity(wallet_address::Entity))
                .await?;
            let _ = database
                .execute(&schema.create_table_from_entity(two_factor::Entity))
                .await?;
            let _ = database.execute_unprepared(
                "INSERT INTO wallet_address (id, user_id, address, chain_id, is_primary, created_at) \
                 VALUES ('wallet', 'owner', 'target-address', 1, 0, '2030-01-01T00:00:00.000Z'); \
                 INSERT INTO two_factor (id, secret, backup_codes, user_id, verified, failed_verification_count, locked_until, created_at, updated_at) \
                 VALUES ('factor', 'stored-secret', 'stored-codes', 'owner', 0, 0, NULL, '2030-01-01T00:00:00.000Z', '2030-01-01T00:00:00.000Z')",
            ).await?;
            let before_wallet = wallet_address::Entity::find().all(&database).await?;
            let before_factor = two_factor::Entity::find().all(&database).await?;
            assert_eq!(before_wallet.len(), 1);
            assert_eq!(before_factor.len(), 1);
            let trace = Trace::default();
            let allocation = Arc::new(AtomicUsize::new(0));
            let invalid: FieldValue =
                FieldMap::from([("driver-invalid".into(), true.into())]).into();
            let failure = callback(&trace, &allocation, "second");
            let later = callback(&trace, &allocation, "later");
            let (first, second) = if array {
                (vec![invalid].into(), vec![failure, later].into())
            } else {
                (invalid, failure)
            };
            let store = SeaOrmStore::<BundledSchema>::new(AuthConfig::default(), database.clone());
            let result: AuthResult<()> = if model == "walletAddress" {
                store
                    .get_wallet_address_value(&first, Some(&second))
                    .await
                    .map(|_| ())
            } else {
                store
                    .compare_exchange_two_factor_backup_codes(
                        &SchemaValue::from_field(first),
                        &second,
                        "must-not-persist".into(),
                    )
                    .await
                    .map(|_| ())
            };
            let Err(AuthError::Internal(message)) = result else {
                return Err(AuthError::internal(format!(
                    "Expected the original {model} callback error: {result:?}"
                ))
                .into());
            };
            assert_eq!(message, "plugin-selector-second");
            assert_eq!(message.as_ptr() as usize, allocation.load(Ordering::SeqCst));
            assert_eq!(take_trace(&trace)?, ["second"]);
            assert_eq!(
                wallet_address::Entity::find().all(&database).await?,
                before_wallet
            );
            assert_eq!(
                two_factor::Entity::find().all(&database).await?,
                before_factor
            );
        }
    }
    Ok(())
}

#[tokio::test]
async fn user_id_in_parses_all_items_before_driver_values() -> Result<(), Box<dyn std::error::Error>>
{
    let mut options = ConnectOptions::new("sqlite::memory:");
    let _ = options.max_connections(1);
    let database = Database::connect(options).await?;
    let _ = database
        .execute(
            &Schema::new(database.get_database_backend()).create_table_from_entity(user::Entity),
        )
        .await?;
    let _ = database.execute_unprepared(
        "INSERT INTO users (id, name, email, email_verified, image, created_at, updated_at) \
         VALUES ('target', 'Target', 'target@plugin-selector.test', 1, NULL, '2030-01-01T00:00:00.000Z', '2030-01-01T00:00:00.000Z'), \
         ('retained', 'Retained', 'retained@plugin-selector.test', 0, NULL, '2030-01-01T00:00:00.000Z', '2030-01-01T00:00:00.000Z')",
    ).await?;
    let before = user::Entity::find()
        .order_by_asc(user::Column::Id)
        .all(&database)
        .await?;
    assert_eq!(before.len(), 2);
    let trace = Trace::default();
    let allocation = Arc::new(AtomicUsize::new(0));
    let ids = [
        FieldMap::from([("driver-invalid".into(), true.into())]).into(),
        callback(&trace, &allocation, "second"),
        callback(&trace, &allocation, "later"),
    ];
    let store = SeaOrmStore::<BundledSchema>::new(AuthConfig::default(), database.clone());
    let result = store.list_users_by_id_values(&ids, 10.0).await;
    let Err(AuthError::Internal(message)) = result else {
        return Err(AuthError::internal(format!(
            "Expected the original User IN callback error: {result:?}"
        ))
        .into());
    };
    assert_eq!(message, "plugin-selector-second");
    assert_eq!(message.as_ptr() as usize, allocation.load(Ordering::SeqCst));
    assert_eq!(take_trace(&trace)?, ["second"]);
    assert_eq!(
        user::Entity::find()
            .order_by_asc(user::Column::Id)
            .all(&database)
            .await?,
        before
    );
    Ok(())
}
