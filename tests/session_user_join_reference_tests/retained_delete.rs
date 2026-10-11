use super::*;
use better_auth_core::store::database_hooks::{
    DatabaseHookContext, DatabaseHookControl, DatabaseHooks,
};
use tokio::sync::oneshot;

#[derive(Default)]
struct DeleteHooks {
    before: AtomicUsize,
    after: AtomicUsize,
}

#[better_auth_core::database_hooks()]
impl<S: AuthSchema> DatabaseHooks<S> for DeleteHooks {
    async fn before_delete_session(
        &self,
        _: &SessionView,
        _: &DatabaseHookContext<'_, S>,
    ) -> AuthResult<DatabaseHookControl> {
        let _ = self.before.fetch_add(1, Ordering::SeqCst);
        Ok(DatabaseHookControl::Continue)
    }

    async fn after_delete_session(
        &self,
        _: &SessionView,
        _: &DatabaseHookContext<'_, S>,
    ) -> AuthResult<()> {
        let _ = self.after.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
}

async fn check_delete<S: AuthSchema>(
    writer: Arc<dyn AuthStore<S>>,
    storage: Storage,
) -> TestResult {
    storage::seed(writer.as_ref(), "alternate-session-reference").await?;
    let mut expected = storage.snapshot(TABLES).await?;
    let sessions = expected
        .get_mut("session")
        .ok_or("Missing Session storage")?;
    assert_eq!(sessions.len(), 2);
    sessions.clear();
    let (sender, mut calls) = mpsc::unbounded_channel();
    let (complete, mut completions) = mpsc::unbounded_channel();
    let marker: FieldValue =
        FieldMap::from([("identity".into(), "retained-session-body".into())]).into();
    let mut config = config("default", false, None);
    for name in ["token", "userAgent"] {
        config
            .session
            .fields_mut()
            .entry(name.into())
            .or_default()
            .transform = Some(FieldTransforms {
            output: Some(callback(
                &sender,
                &complete,
                writer.clone(),
                marker.clone(),
                name,
            )),
            ..Default::default()
        });
    }
    let hooks = Arc::new(DeleteHooks::default());
    let reader = writer.with_runtime(config.into(), vec![hooks.clone()], Default::default())?;
    let mut request = AuthRequest::new(HttpMethod::Post, "/retained-session");
    let _ = request
        .headers
        .insert("x-contract".into(), "retained-session".into());
    let mut context = RequestHookContext::from_request(&request)?;
    context.operation_id = Some("retained-session".into());
    context.body = marker.clone();
    let (deleted, deletion) = oneshot::channel();
    let (resume, resumed) = oneshot::channel();
    let pending = tokio::spawn(with_request_hook_context_value(context, async move {
        let tokens = [TOKEN.into(), format!("{TOKEN}-b")];
        reader.delete_sessions(&tokens).await?;
        check_context(&marker)?;
        deleted
            .send(())
            .map_err(|_| AuthError::internal("Session deletion observer closed"))?;
        resumed
            .await
            .map_err(|_| AuthError::internal("Session request continuation closed"))?;
        check_context(&marker)?;
        assert!(
            reader
                .get_session_snapshots(&tokens, false)
                .await?
                .is_empty()
        );
        Ok::<(), AuthError>(())
    }));
    let rejected = calls
        .recv()
        .await
        .ok_or("Expected first deleted Session parent")?;
    let peer = calls
        .recv()
        .await
        .ok_or("Expected retained deleted Session parent")?;
    assert_eq!((rejected.name, peer.name), ("token", "token"));
    let rejected_token = rejected
        .value
        .as_str()
        .ok_or("Expected rejected Session token")?
        .to_owned();
    let peer_token = peer
        .value
        .as_str()
        .ok_or("Expected retained Session token")?
        .to_owned();
    assert_ne!(suffix(&rejected_token)?, suffix(&peer_token)?);
    assert!(matches!(
        calls.try_recv(),
        Err(mpsc::error::TryRecvError::Empty)
    ));
    rejected
        .reply
        .send(Err(AuthError::Config(
            "original-session-delete-error".into(),
        )))
        .map_err(|_| "Rejected Session delete callback closed")?;
    tokio::time::timeout(Duration::from_secs(5), deletion).await??;
    assert!(!peer.reply.is_closed());
    assert!(!pending.is_finished());
    finished(&mut completions, false, "token", &rejected_token).await?;
    assert_eq!(hooks.before.load(Ordering::SeqCst), 0);
    assert_eq!(hooks.after.load(Ordering::SeqCst), 0);
    assert_eq!(storage.snapshot(TABLES).await?, expected);
    assert!(current_request_hook_context().is_none());
    answer(peer)?;
    finished(&mut completions, true, "token", &peer_token).await?;
    let late = next(&mut calls, "userAgent", "session-user-join-reference").await?;
    late.reply
        .send(Err(AuthError::Config("late-session-delete-error".into())))
        .map_err(|_| "Late Session delete callback closed")?;
    finished(
        &mut completions,
        false,
        "userAgent",
        "session-user-join-reference",
    )
    .await?;
    resume
        .send(())
        .map_err(|_| "Session request ended before the late error")?;
    tokio::time::timeout(Duration::from_secs(5), pending).await???;
    assert_eq!(hooks.before.load(Ordering::SeqCst), 0);
    assert_eq!(hooks.after.load(Ordering::SeqCst), 0);
    assert_eq!(storage.snapshot(TABLES).await?, expected);
    assert!(current_request_hook_context().is_none());
    assert!(matches!(
        calls.try_recv(),
        Err(mpsc::error::TryRecvError::Empty)
    ));
    assert!(matches!(
        completions.try_recv(),
        Err(mpsc::error::TryRecvError::Empty)
    ));
    Ok(())
}

#[tokio::test]
async fn memory_delete_sessions_catches_original_and_late_projection_errors() -> TestResult {
    let raw = EphemeralStore::new(Arc::new(config("default", false, None)));
    let writer: Arc<dyn AuthStore<StatelessSchema>> = Arc::new(raw.clone());
    tokio::time::timeout(
        Duration::from_secs(10),
        check_delete(writer, Storage::Memory(Box::new(raw))),
    )
    .await?
}

#[tokio::test]
async fn sqlite_delete_sessions_catches_original_and_late_projection_errors() -> TestResult {
    let database = storage::sqlite().await?;
    let writer: Arc<dyn AuthStore<storage::Core>> = Arc::new(SeaOrmStore::new(
        config("default", false, None),
        database.clone(),
    ));
    tokio::time::timeout(
        Duration::from_secs(10),
        check_delete(writer, Storage::Sqlite(database)),
    )
    .await?
}
