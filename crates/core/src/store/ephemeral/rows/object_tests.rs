#![expect(
    clippy::panic_in_result_fn,
    reason = "Assertions verify row ownership; fixture and object access errors propagate."
)]

use super::*;
use crate::store::ephemeral::EphemeralStore;

fn required<T>(value: Option<T>) -> AuthResult<T> {
    value.ok_or_else(|| AuthError::internal("Expected a retained object fixture"))
}

fn detached<T: ObjectRow + FromFieldMap + Clone + Send + 'static>() -> AuthResult<()> {
    let mut rows = Rows::default();
    let original = rows.push_ref(T::from_field_values(
        [
            ("id".into(), "same-id".into()),
            ("name".into(), "original".into()),
        ]
        .into(),
    )?);
    let retained = original.field_value();
    let handle = required(retained.as_object())?;
    let _ = rows.remove_ref(&original)?;
    let replacement = rows.push_ref(T::from_field_values(
        [
            ("id".into(), "same-id".into()),
            ("name".into(), "replacement".into()),
        ]
        .into(),
    )?);
    assert_eq!(handle.set("name", false.into())?, Some("original".into()));
    assert_eq!(handle.delete("id")?, Some("same-id".into()));
    assert_eq!(handle.set("id", FieldValue::Undefined)?, None);
    assert_eq!(handle.get("id")?, Some(FieldValue::Undefined));
    assert_eq!(handle.delete("id")?, Some(FieldValue::Undefined));
    assert_eq!(handle.get("id")?, None);
    assert_eq!(
        original.read(AuthRecordFields::field_values)?,
        [("name".into(), false.into())].into()
    );
    assert_eq!(
        replacement.read(AuthRecordFields::field_values)?,
        [
            ("id".into(), "same-id".into()),
            ("name".into(), "replacement".into()),
        ]
        .into()
    );
    assert!(!handle.same_object(required(replacement.field_value().as_object())?));
    Ok(())
}

#[test]
fn retained_map_and_user_handles_do_not_rebind_after_deletion() -> AuthResult<()> {
    detached::<FieldMap>()?;
    detached::<crate::UserView>()
}

#[tokio::test]
async fn mutable_handles_keep_transaction_rollback_and_commit_ownership() -> AuthResult<()> {
    let store = EphemeralStore::default();
    let live = store.lock()?.accounts.push_ref(
        [
            ("id".into(), "account".into()),
            (
                "payload".into(),
                FieldMap::from([("value".into(), 0.into())]).into(),
            ),
        ]
        .into(),
    );
    let original = live.read(AuthRecordFields::field_values)?;
    let (base, rollback, queue) = store.begin_adapter_transaction()?;
    let row = required(rollback.lock()?.accounts.first_ref(|_| true)?)?;
    let retained = row.field_value();
    let object = required(retained.as_object())?;
    let payload = required(object.get("payload")?)?;
    let _ = required(payload.as_object())?.set("value", 1.into())?;
    let _ = object.set("phase", "rolled-back".into())?;
    drop((base, rollback, queue));
    let _ = object.set("phase", "retained-after-rollback".into())?;
    assert_eq!(live.read(AuthRecordFields::field_values)?, original);

    let (base, commit, queue) = store.begin_adapter_transaction()?;
    let committed = required(commit.lock()?.accounts.first_ref(|_| true)?)?;
    let value = committed.field_value();
    let payload = required(required(value.as_object())?.get("payload")?)?;
    let _ = required(payload.as_object())?.set("value", 2.into())?;
    store.commit_transaction(base, commit, queue).await?;
    assert!(store.lock()?.accounts.contains_ref(&committed));
    assert!(!store.lock()?.accounts.contains_ref(&live));
    let _ = required(value.as_object())?.set("phase", "after-commit".into())?;
    assert_eq!(
        required(store.lock()?.accounts.first_ref(|_| true)?)?
            .read(AuthRecordFields::field_values)?,
        [
            ("id".into(), "account".into()),
            (
                "payload".into(),
                FieldMap::from([("value".into(), 2.into())]).into()
            ),
            ("phase".into(), "after-commit".into()),
        ]
        .into()
    );
    assert_eq!(live.read(AuthRecordFields::field_values)?, original);
    Ok(())
}
