use super::*;
use super::{adapter_storage_snapshot::Storage, field_projection_gate::Call};
use better_auth_core::{
    UpdateUser,
    hooks::{RequestHookContext, current_request_hook_context, with_request_hook_context_value},
    store::{StatelessSchema, schema::EntityRole},
};
use std::time::Duration;
use tokio::sync::mpsc;

#[path = "retained_delete.rs"]
mod deletion;

const TABLES: &[(&str, &str, EntityRole)] = &[
    ("user", "user", EntityRole::User),
    ("session", "session", EntityRole::Session),
    ("account", "account", EntityRole::Account),
    ("verification", "verification", EntityRole::Verification),
];
type Completion = (bool, &'static str, FieldValue);

fn check_context(marker: &FieldValue) -> AuthResult<()> {
    let context = current_request_hook_context()
        .ok_or_else(|| AuthError::internal("Session callback lost request context"))?;
    assert_eq!(context.path.as_deref(), Some("/retained-session"));
    assert_eq!(context.operation_id.as_deref(), Some("retained-session"));
    assert_eq!(
        context.headers.get("x-contract").map(String::as_str),
        Some("retained-session")
    );
    assert_eq!(context.request.path(), "/retained-session");
    assert_eq!(
        context
            .request
            .headers
            .get("x-contract")
            .map(String::as_str),
        Some("retained-session")
    );
    assert!(context.body.strict_equals(marker));
    Ok(())
}

fn callback<S: AuthSchema>(
    sender: &mpsc::UnboundedSender<Call>,
    completions: &mpsc::UnboundedSender<Completion>,
    writer: Arc<dyn AuthStore<S>>,
    marker: FieldValue,
    name: &'static str,
) -> UserFieldTransform {
    let gate = field_projection_gate::callback(sender, name, std::convert::identity);
    let completions = completions.clone();
    UserFieldTransform::new_async(move |value| {
        let (gate, writer, marker, completions) = (
            gate.clone(),
            writer.clone(),
            marker.clone(),
            completions.clone(),
        );
        async move {
            check_context(&marker)?;
            let result = gate.call(value.clone()).await;
            check_context(&marker)?;
            if name == "name" && result.is_ok() {
                let suffix = value
                    .as_str()
                    .and_then(|name| name.strip_prefix("User "))
                    .ok_or_else(|| AuthError::internal("Expected seeded Session User name"))?;
                let date: FieldDate = "2030-01-02T03:04:05.000Z"
                    .parse::<chrono::DateTime<chrono::Utc>>()
                    .map_err(|error| AuthError::internal(error.to_string()))?
                    .into();
                let _ = writer
                    .update_user(
                        &format!("user-{suffix}"),
                        UpdateUser {
                            image: Some("after-release".into()).into(),
                            additional_fields: [("updatedAt".into(), date.into())].into(),
                            ..Default::default()
                        },
                    )
                    .await?;
                check_context(&marker)?;
            }
            completions
                .send((result.is_ok(), name, value))
                .map_err(|_| AuthError::internal("Session completion observer closed"))?;
            result
        }
    })
}

async fn next(
    receiver: &mut mpsc::UnboundedReceiver<Call>,
    name: &str,
    value: &str,
) -> TestResult<Call> {
    let call = receiver
        .recv()
        .await
        .ok_or("Missing Session field callback")?;
    assert_eq!((call.name, &call.value), (name, &FieldValue::from(value)));
    Ok(call)
}

fn answer(call: Call) -> TestResult {
    call.reply
        .send(Ok(call.value))
        .map_err(|_| "Session field callback was cancelled")?;
    Ok(())
}

async fn finished(
    receiver: &mut mpsc::UnboundedReceiver<Completion>,
    ok: bool,
    name: &str,
    value: &str,
) -> TestResult {
    assert_eq!(
        receiver.recv().await.ok_or("Missing Session completion")?,
        (ok, name, FieldValue::from(value))
    );
    Ok(())
}

fn suffix(token: &str) -> TestResult<&'static str> {
    if token == TOKEN {
        Ok("a")
    } else if token == format!("{TOKEN}-b") {
        Ok("b")
    } else {
        Err(format!("Unexpected seeded Session token {token}").into())
    }
}

async fn check<S: AuthSchema>(
    writer: Arc<dyn AuthStore<S>>,
    storage: Storage,
    joins: bool,
) -> TestResult {
    storage::seed(writer.as_ref(), "alternate-session-reference").await?;
    let before = storage.snapshot(TABLES).await?;
    let (sender, mut calls) = mpsc::unbounded_channel();
    let (complete, mut completions) = mpsc::unbounded_channel();
    let marker: FieldValue =
        FieldMap::from([("identity".into(), "retained-session-body".into())]).into();
    let mut config = config("default", joins, None);
    for name in ["token", "userAgent", "name", "image"] {
        let transform = callback(&sender, &complete, writer.clone(), marker.clone(), name);
        let fields = if matches!(name, "name" | "image") {
            config.user.fields_mut()
        } else {
            config.session.fields_mut()
        };
        fields.entry(name.into()).or_default().transform = Some(FieldTransforms {
            output: Some(transform),
            ..Default::default()
        });
    }
    let reader = writer.with_runtime(config.into(), Vec::new(), Default::default())?;
    let mut request = AuthRequest::new(HttpMethod::Get, "/retained-session");
    let _ = request
        .headers
        .insert("x-contract".into(), "retained-session".into());
    let mut context = RequestHookContext::from_request(&request)?;
    context.operation_id = Some("retained-session".into());
    context.body = marker;
    let pending = tokio::spawn(with_request_hook_context_value(context, async move {
        reader
            .get_session_snapshots(&[TOKEN.into(), format!("{TOKEN}-b")], false)
            .await
    }));
    let rejected = calls.recv().await.ok_or("Expected first Session parent")?;
    let peer = calls
        .recv()
        .await
        .ok_or("Expected retained Session parent")?;
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
    let original = String::from("original-session-parent-error");
    let original_pointer = original.as_ptr() as usize;
    rejected
        .reply
        .send(Err(AuthError::Config(original)))
        .map_err(|_| "Rejected Session callback closed")?;
    let outcome = tokio::time::timeout(Duration::from_secs(5), pending).await??;
    let Err(AuthError::Config(original)) = outcome else {
        return Err("Expected original Session error before the peer gate opens".into());
    };
    assert_eq!(original, "original-session-parent-error");
    assert_eq!(original.as_ptr() as usize, original_pointer);
    assert!(!peer.reply.is_closed());
    assert!(current_request_hook_context().is_none());
    finished(&mut completions, false, "token", &rejected_token).await?;
    assert_eq!(storage.snapshot(TABLES).await?, before);
    answer(peer)?;
    finished(&mut completions, true, "token", &peer_token).await?;
    answer(next(&mut calls, "userAgent", "session-user-join-reference").await?)?;
    finished(
        &mut completions,
        true,
        "userAgent",
        "session-user-join-reference",
    )
    .await?;
    let suffix = suffix(&peer_token)?;
    let name = format!("User {suffix}");
    answer(next(&mut calls, "name", &name).await?)?;
    finished(&mut completions, true, "name", &name).await?;
    let image = if matches!(storage, Storage::Memory(_)) {
        "after-release".into()
    } else {
        format!("image-{suffix}")
    };
    answer(next(&mut calls, "image", &image).await?)?;
    finished(&mut completions, true, "image", &image).await?;
    assert_eq!(original.as_ptr() as usize, original_pointer);
    assert!(current_request_hook_context().is_none());
    assert!(matches!(
        calls.try_recv(),
        Err(mpsc::error::TryRecvError::Empty)
    ));
    assert!(matches!(
        completions.try_recv(),
        Err(mpsc::error::TryRecvError::Empty)
    ));
    let mut expected = before;
    let user_id = FieldValue::from(format!("user-{suffix}"));
    let user = expected
        .get_mut("user")
        .and_then(|users| users.iter_mut().find(|row| row.get("id") == Some(&user_id)))
        .ok_or("Expected retained Session User in complete storage")?;
    let _ = user.insert("image".into(), "after-release".into());
    assert_eq!(storage.snapshot(TABLES).await?, expected);
    Ok(())
}

async fn memory(joins: bool) -> TestResult {
    let raw = EphemeralStore::new(Arc::new(config("default", joins, None)));
    let writer: Arc<dyn AuthStore<StatelessSchema>> = Arc::new(raw.clone());
    tokio::time::timeout(
        Duration::from_secs(10),
        check(writer, Storage::Memory(Box::new(raw)), joins),
    )
    .await?
}

async fn sqlite(joins: bool) -> TestResult {
    let database = storage::sqlite().await?;
    let writer: Arc<dyn AuthStore<storage::Core>> = Arc::new(SeaOrmStore::new(
        config("default", joins, None),
        database.clone(),
    ));
    tokio::time::timeout(
        Duration::from_secs(10),
        check(writer, Storage::Sqlite(database), joins),
    )
    .await?
}

#[tokio::test]
async fn memory_fallback_session_retains_the_peer_after_original_error() -> TestResult {
    memory(false).await
}
#[tokio::test]
async fn memory_native_session_retains_the_peer_after_original_error() -> TestResult {
    memory(true).await
}
#[tokio::test]
async fn sqlite_fallback_session_retains_the_peer_after_original_error() -> TestResult {
    sqlite(false).await
}
#[tokio::test]
async fn sqlite_native_session_retains_the_peer_after_original_error() -> TestResult {
    sqlite(true).await
}
