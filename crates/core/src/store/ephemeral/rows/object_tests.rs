#![expect(
    clippy::panic_in_result_fn,
    reason = "Assertions verify row ownership; fixture and object access errors propagate."
)]

use super::*;
use crate::field_value::FieldObjectSource;
use crate::store::ephemeral::EphemeralStore;
use crate::store::ephemeral::table::TableRef;
use crate::store::schema::EntityRole;
use std::sync::Weak;
use std::sync::atomic::{AtomicUsize, Ordering};

fn required<T>(value: Option<T>) -> AuthResult<T> {
    value.ok_or_else(|| AuthError::internal("Expected a retained object fixture"))
}

fn detached<T: ObjectRow + FromFieldMap + Clone + Send + 'static>() -> AuthResult<()> {
    let mut rows = TableRef::new(Arc::default());
    let original = rows.push(T::from_field_values(
        [
            ("id".into(), "same-id".into()),
            ("name".into(), "original".into()),
        ]
        .into(),
    )?)?;
    let retained = original.field_value();
    let handle = required(retained.as_object())?;
    rows = rows.without_refs(std::slice::from_ref(&original))?;
    let replacement = rows.push(T::from_field_values(
        [
            ("id".into(), "same-id".into()),
            ("name".into(), "replacement".into()),
        ]
        .into(),
    )?)?;
    assert_eq!(handle.set("name", false.into())?, Some("original".into()));
    assert_eq!(handle.delete("id")?, Some("same-id".into()));
    assert_eq!(handle.set("id", FieldValue::Undefined)?, None);
    assert_eq!(handle.get("id")?, Some(FieldValue::Undefined));
    assert_eq!(handle.delete("id")?, Some(FieldValue::Undefined));
    assert_eq!(handle.get("id")?, None);
    assert_eq!(
        original.shallow_fields()?,
        [("name".into(), false.into())].into()
    );
    assert_eq!(
        replacement.shallow_fields()?,
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
    let live = store.operation(|op| {
        op.capture_table(EntityRole::Account)?.push(
            [
                ("id".into(), "account".into()),
                (
                    "payload".into(),
                    FieldMap::from([("value".into(), 0.into())]).into(),
                ),
            ]
            .into(),
        )
    })?;
    let original = live.shallow_fields()?;
    let (base, rollback, queue) = store.begin_adapter_transaction()?;
    let row = required(rollback.operation(|op| op.capture_table(EntityRole::Account)?.row_at(0))?)?;
    let retained = row.field_value();
    let object = required(retained.as_object())?;
    let payload = required(object.get("payload")?)?;
    let _ = required(payload.as_object())?.set("value", 1.into())?;
    let _ = object.set("phase", "rolled-back".into())?;
    drop((base, rollback, queue));
    let _ = object.set("phase", "retained-after-rollback".into())?;
    assert_eq!(live.shallow_fields()?, original);

    let (base, commit, queue) = store.begin_adapter_transaction()?;
    let committed =
        required(commit.operation(|op| op.capture_table(EntityRole::Account)?.row_at(0))?)?;
    let value = committed.field_value();
    let payload = required(required(value.as_object())?.get("payload")?)?;
    let _ = required(payload.as_object())?.set("value", 2.into())?;
    store.commit_transaction(base, commit, queue).await?;
    assert!(store.operation(|op| {
        op.capture_table(EntityRole::Account)?
            .contains_ref(&committed)
    })?);
    assert!(!store.operation(|op| op.capture_table(EntityRole::Account)?.contains_ref(&live))?);
    let _ = required(value.as_object())?.set("phase", "after-commit".into())?;
    assert_eq!(
        required(store.operation(|op| op.capture_table(EntityRole::Account)?.row_at(0))?)?
            .shallow_fields()?,
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
    assert_eq!(live.shallow_fields()?, original);
    Ok(())
}

struct InvitationGraphSource {
    row: Weak<Mutex<FieldMap>>,
    reads: AtomicUsize,
    failure: Mutex<Option<AuthError>>,
}

impl FieldObjectSource for InvitationGraphSource {
    fn get(&self, name: &str) -> AuthResult<Option<FieldValue>> {
        Ok(self.snapshot_fields()?.get(name).cloned())
    }

    fn set(&self, _: String, _: FieldValue) -> AuthResult<Option<FieldValue>> {
        Err(AuthError::internal("Clone probe fields are immutable"))
    }

    fn delete(&self, _: &str) -> AuthResult<Option<FieldValue>> {
        Err(AuthError::internal("Clone probe fields are immutable"))
    }

    fn snapshot_fields(&self) -> AuthResult<FieldMap> {
        let source = required(self.row.upgrade())?;
        // A failed try_lock reports the regression without blocking the test process.
        let row = source
            .try_lock()
            .map_err(|_| AuthError::internal("Invitation graph copy retained its row lock"))?;
        if self.reads.fetch_add(1, Ordering::SeqCst) == 1
            && let Some(error) = lock(&self.failure)?.take()
        {
            return Err(error);
        }
        Ok([("name".into(), row.get("name").cloned().unwrap_or_default())].into())
    }

    fn identity(&self) -> usize {
        std::ptr::from_ref(self) as usize
    }
}

#[tokio::test]
async fn invitation_graph_copies_release_rows_and_preserve_aliases_and_failure_ownership()
-> AuthResult<()> {
    use crate::store::{InvitationStore, SessionStore, TeamMemberLimits};
    use chrono::Utc;

    for fail_copy in [false, true] {
        let store = EphemeralStore::default();
        let sources: Vec<_> = ["first", "second"]
            .into_iter()
            .map(|id| {
                store.operation(|op| {
                    op.capture_table(EntityRole::Team)?.push(
                        [
                            ("id".into(), id.into()),
                            ("name".into(), "Shared graph".into()),
                            ("organizationId".into(), "organization".into()),
                            ("createdAt".into(), Utc::now().into()),
                            ("memberCount".into(), 0.into()),
                        ]
                        .into(),
                    )
                })
            })
            .collect::<AuthResult<_>>()?;
        let failure = "Invitation graph source failed".to_owned();
        let original_error = failure.as_ptr() as usize;
        let graph = Arc::new(InvitationGraphSource {
            row: Arc::downgrade(&required(sources.first())?.0),
            reads: AtomicUsize::new(0),
            failure: Mutex::new(fail_copy.then_some(AuthError::Internal(failure))),
        });
        let shared = FieldValue::Object(crate::FieldObject::from_source(graph.clone()));
        for row in &sources {
            row.apply_patch(
                [
                    ("graph".into(), shared.clone()),
                    ("alias".into(), shared.clone()),
                ]
                .into(),
            )?;
        }
        let mut input = crate::CreateInvitation::new(
            "organization",
            "recipient@example.com",
            "member",
            "inviter",
            (Utc::now() + chrono::Duration::days(1)).into(),
        );
        input.team_id = Some("first,second".into());
        let invitation = store.create_invitation(input).await?;
        let result = store
            .accept_invitation_with_teams(
                invitation.id.typed()?,
                "recipient",
                None,
                true,
                TeamMemberLimits::Fixed(Some(1)),
            )
            .await;
        assert_eq!(graph.reads.load(Ordering::SeqCst), 2);
        if fail_copy {
            assert!(matches!(result, Err(AuthError::Internal(message))
                if message == "Invitation graph source failed"
                    && message.as_ptr() as usize == original_error));
        } else {
            let (member, accepted, session) = result?;
            assert_eq!(member.user_id, "recipient");
            assert_eq!(accepted.status.field_value(), "accepted".into());
            assert!(session.is_none());
        }
        let state = store.operation(|op| op.capture_state())?;
        assert_eq!(state.members.len()?, usize::from(!fail_copy));
        assert_eq!(state.team_members.len()?, if fail_copy { 0 } else { 2 });
        assert_eq!(state.sessions.len()?, 0);
        assert_eq!(
            required(state.invitations.snapshot()?.first())?.get("status"),
            Some(&FieldValue::from(if fail_copy {
                "pending"
            } else {
                "accepted"
            }))
        );
        let teams = state.teams.snapshot()?;
        let first = required(teams.first())?;
        let cloned = required(required(first.get("graph"))?.as_object())?;
        if !fail_copy {
            assert_eq!(
                cloned.snapshot_fields()?,
                [("name".into(), "Shared graph".into())].into()
            );
        }
        for (team, original) in teams.iter().zip(&sources) {
            assert_eq!(
                team.get("memberCount"),
                Some(&FieldValue::from(if fail_copy { 0 } else { 1 }))
            );
            assert_eq!(state.teams.contains_ref(original)?, fail_copy);
            for name in ["graph", "alias"] {
                let value = required(required(team.get(name))?.as_object())?;
                assert!(cloned.same_object(value));
                assert_eq!(value.same_object(required(shared.as_object())?), fail_copy);
            }
        }
    }
    Ok(())
}
