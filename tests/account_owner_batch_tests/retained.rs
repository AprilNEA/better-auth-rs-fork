use super::*;
use better_auth_core::{
    AuthRequest, FieldDate, HttpMethod, UpdateUser,
    hooks::{RequestHookContext, current_request_hook_context, with_request_hook_context_value},
    store::{StatelessSchema, schema::EntityRole},
};
use better_auth_seaorm::sea_orm::{ConnectionTrait, DatabaseConnection, DbBackend, Statement};
use std::{collections::BTreeMap, time::Duration};

const PROVIDER: &str = "retained-provider";
const SUBJECT: &str = "duplicate-subject";
const DUPLICATE: &str = "Multiple accounts match the same accountId for provider \"retained-provider\". Resolve duplicate account identities before continuing.";

enum Storage {
    Memory(Box<EphemeralStore>),
    Sqlite(DatabaseConnection),
}

impl Storage {
    async fn snapshot(&self) -> AuthResult<BTreeMap<String, Vec<FieldMap>>> {
        let mut snapshot = BTreeMap::new();
        for (name, table, role) in [
            ("user", "users", EntityRole::User),
            ("account", "accounts", EntityRole::Account),
            ("session", "sessions", EntityRole::Session),
            ("verification", "verifications", EntityRole::Verification),
        ] {
            let mut rows = match self {
                Self::Memory(store) => store.storage_rows(role)?,
                Self::Sqlite(database) => {
                    let columns = database
                        .query_all_raw(Statement::from_string(
                            DbBackend::Sqlite,
                            format!("PRAGMA table_info(\"{table}\")"),
                        ))
                        .await
                        .map_err(|error| AuthError::internal(error.to_string()))?;
                    let columns = columns
                        .iter()
                        .map(|row| row.try_get::<String>("", "name"))
                        .collect::<Result<Vec<_>, _>>()
                        .map_err(|error| AuthError::internal(error.to_string()))?;
                    let columns = columns
                        .iter()
                        .map(|name| format!("'{name}',\"{name}\""))
                        .collect::<Vec<_>>()
                        .join(",");
                    database.query_all_raw(Statement::from_string(DbBackend::Sqlite,
                        format!("SELECT json_object({columns}) AS value FROM \"{table}\" ORDER BY id"),
                    )).await.map_err(|error| AuthError::internal(error.to_string()))?
                        .into_iter().map(|row| {
                            let json = row.try_get::<String>("", "value")
                                .map_err(|error| AuthError::internal(error.to_string()))?;
                            FieldMap::from_json(serde_json::from_str(&json)?)
                        }).collect::<AuthResult<Vec<_>>>()?
                }
            };
            rows.sort_by(|left, right| {
                left.get("id")
                    .and_then(FieldValue::as_str)
                    .cmp(&right.get("id").and_then(FieldValue::as_str))
            });
            let _ = snapshot.insert(name.into(), rows);
        }
        Ok(snapshot)
    }
}

fn date() -> FieldDate {
    FieldDate::from_milliseconds(1_893_456_000_000.0)
}

async fn seed<S: AuthSchema>(store: &dyn AuthStore<S>) -> AuthResult<()> {
    for label in ["A", "B", "C"] {
        let _ = store
            .create_user(CreateUser {
                id: Some(format!("user-{label}")),
                created_at: Some(date()),
                updated_at: Some(date()),
                image: Some(format!("{label}.png")).into(),
                ..CreateUser::new()
                    .with_name(label)
                    .with_email(format!("{label}@retained-owner.test"))
            })
            .await?;
        let _ = store
            .create_account(CreateAccount {
                id: format!("account-{label}").into(),
                account_id: SUBJECT.into(),
                provider_id: PROVIDER.into(),
                user_id: format!("user-{label}").into(),
                access_token: Some(label.into()).into(),
                refresh_token: Some(label.into()).into(),
                created_at: date().into(),
                updated_at: date().into(),
                ..Default::default()
            })
            .await?;
    }
    Ok(())
}

#[expect(
    clippy::panic_in_result_fn,
    reason = "Assertions verify inherited request data and body identity"
)]
fn check_context(marker: &FieldValue) -> AuthResult<()> {
    let context = current_request_hook_context()
        .ok_or_else(|| AuthError::internal("Account owner callback lost request context"))?;
    assert_eq!(context.path.as_deref(), Some("/retained-account-owner"));
    assert_eq!(
        context.operation_id.as_deref(),
        Some("retained-account-owner")
    );
    assert_eq!(
        context.headers.get("x-contract").map(String::as_str),
        Some("retained-account-owner")
    );
    assert_eq!(context.request.path(), "/retained-account-owner");
    assert_eq!(
        context
            .request
            .headers
            .get("x-contract")
            .map(String::as_str),
        Some("retained-account-owner")
    );
    assert!(context.body.strict_equals(marker));
    Ok(())
}

type Completion = (bool, &'static str, FieldValue);

fn field<S: AuthSchema>(
    sender: &mpsc::UnboundedSender<Event>,
    completions: &mpsc::UnboundedSender<Completion>,
    writer: Arc<dyn AuthStore<S>>,
    marker: FieldValue,
    name: &'static str,
) -> UserFieldConfig {
    let callback = async_callback(sender, name);
    let completions = completions.clone();
    UserFieldConfig {
        transform: Some(FieldTransforms {
            output: Some(UserFieldTransform::new_async(move |value| {
                let (callback, writer, marker, completions) = (
                    callback.clone(),
                    writer.clone(),
                    marker.clone(),
                    completions.clone(),
                );
                async move {
                    check_context(&marker)?;
                    let result = callback.call(value.clone()).await;
                    check_context(&marker)?;
                    if name == "name" && result.is_ok() {
                        let label = value
                            .as_str()
                            .ok_or_else(|| AuthError::internal("Expected fixture User name"))?;
                        let _ = writer
                            .update_user(
                                &format!("user-{label}"),
                                UpdateUser {
                                    image: Some("after-release".into()).into(),
                                    additional_fields: [("updatedAt".into(), date().into())].into(),
                                    ..Default::default()
                                },
                            )
                            .await?;
                        check_context(&marker)?;
                    }
                    completions
                        .send((result.is_ok(), name, value))
                        .map_err(|_| AuthError::internal("Owner completion observer closed"))?;
                    result
                }
            })),
            ..Default::default()
        }),
        ..Default::default()
    }
}

async fn finished(
    receiver: &mut mpsc::UnboundedReceiver<Completion>,
    ok: bool,
    name: &str,
    value: &str,
) {
    assert_eq!(
        receiver.recv().await.unwrap(),
        (ok, name, FieldValue::from(value))
    );
}

async fn check<S: AuthSchema>(writer: Arc<dyn AuthStore<S>>, storage: Storage, joins: bool) {
    seed(writer.as_ref()).await.unwrap();
    let before = storage.snapshot().await.unwrap();
    let (sender, mut calls) = mpsc::unbounded_channel();
    let (completed, mut completions) = mpsc::unbounded_channel();
    let marker: FieldValue =
        FieldMap::from([("identity".into(), "retained-owner-body".into())]).into();
    let mut config = AuthConfig::default();
    config.advanced.database.joins = Some(joins);
    config.advanced.database.default_find_many_limit = Some(1.0);
    for name in ["accessToken", "refreshToken", "name", "image"] {
        let declaration = field(&sender, &completed, writer.clone(), marker.clone(), name);
        let fields = if matches!(name, "name" | "image") {
            config.user.fields_mut()
        } else {
            &mut config.account.additional_fields
        };
        let _ = fields.insert(name.into(), declaration);
    }
    let reader = writer
        .with_runtime(config.into(), Vec::new(), Default::default())
        .unwrap();
    let mut request = AuthRequest::new(HttpMethod::Get, "/retained-account-owner");
    let _ = request
        .headers
        .insert("x-contract".into(), "retained-account-owner".into());
    let mut context = RequestHookContext::from_request(&request).unwrap();
    context.operation_id = Some("retained-account-owner".into());
    context.body = marker;
    let pending = tokio::spawn(with_request_hook_context_value(context, async move {
        reader.get_account_owner(PROVIDER, SUBJECT).await
    }));
    let Some(Event::Field(rejected)) = calls.recv().await else {
        panic!("Expected first Account parent")
    };
    let Some(Event::Field(peer)) = calls.recv().await else {
        panic!("Expected retained Account parent")
    };
    assert_eq!((rejected.name, peer.name), ("accessToken", "accessToken"));
    let rejected_label = rejected.value.as_str().unwrap().to_owned();
    let peer_label = peer.value.as_str().unwrap().to_owned();
    assert!(["A", "B", "C"].contains(&rejected_label.as_str()));
    assert!(["A", "B", "C"].contains(&peer_label.as_str()));
    assert_ne!(rejected_label, peer_label);
    assert!(matches!(
        calls.try_recv(),
        Err(mpsc::error::TryRecvError::Empty)
    ));
    let original = String::from("original-account-owner-error");
    let original_pointer = original.as_ptr() as usize;
    rejected
        .reply
        .send(Err(AuthError::Config(original)))
        .unwrap();
    let outcome = tokio::time::timeout(Duration::from_secs(5), pending)
        .await
        .unwrap()
        .unwrap();
    let Err(AuthError::Config(original)) = outcome else {
        panic!("Expected original parent error before duplicate identity rejection")
    };
    assert_eq!(original, "original-account-owner-error");
    assert_eq!(original.as_ptr() as usize, original_pointer);
    assert!(!peer.reply.is_closed());
    assert!(current_request_hook_context().is_none());
    finished(&mut completions, false, "accessToken", &rejected_label).await;
    assert_eq!(storage.snapshot().await.unwrap(), before);
    answer(peer);
    finished(&mut completions, true, "accessToken", &peer_label).await;
    answer(next_field(&mut calls, "refreshToken", &peer_label).await);
    finished(&mut completions, true, "refreshToken", &peer_label).await;
    answer(next_field(&mut calls, "name", &peer_label).await);
    finished(&mut completions, true, "name", &peer_label).await;
    let image = if matches!(storage, Storage::Memory(_)) {
        "after-release".into()
    } else {
        format!("{peer_label}.png")
    };
    answer(next_field(&mut calls, "image", &image).await);
    finished(&mut completions, true, "image", &image).await;
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
    let user_id = FieldValue::from(format!("user-{peer_label}"));
    let user = expected
        .get_mut("user")
        .unwrap()
        .iter_mut()
        .find(|row| row.get("id") == Some(&user_id))
        .unwrap();
    let _ = user.insert("image".into(), "after-release".into());
    assert_eq!(storage.snapshot().await.unwrap(), expected);
    let mut control = AuthConfig::default();
    control.advanced.database.joins = Some(joins);
    control.advanced.database.default_find_many_limit = Some(1.0);
    let control = writer
        .with_runtime(control.into(), Vec::new(), Default::default())
        .unwrap();
    let Err(AuthError::Internal(message)) = control.get_account_owner(PROVIDER, SUBJECT).await
    else {
        panic!("Successful parents must still reject duplicate identities")
    };
    assert_eq!(message, DUPLICATE);
    assert_eq!(storage.snapshot().await.unwrap(), expected);
}

async fn memory(joins: bool) {
    let raw = EphemeralStore::default();
    let writer: Arc<dyn AuthStore<StatelessSchema>> = Arc::new(raw.clone());
    tokio::time::timeout(
        Duration::from_secs(10),
        check(writer, Storage::Memory(Box::new(raw)), joins),
    )
    .await
    .unwrap();
}

async fn sqlite(joins: bool) {
    let database = Database::connect("sqlite::memory:").await.unwrap();
    migrator::run_migrations(&database).await.unwrap();
    let writer: Arc<dyn AuthStore<BundledSchema>> =
        Arc::new(SeaOrmStore::new(AuthConfig::default(), database.clone()));
    tokio::time::timeout(
        Duration::from_secs(10),
        check(writer, Storage::Sqlite(database), joins),
    )
    .await
    .unwrap();
}

#[tokio::test]
async fn memory_fallback_account_owner_retains_the_peer_after_original_error() {
    memory(false).await;
}
#[tokio::test]
async fn memory_native_account_owner_retains_the_peer_after_original_error() {
    memory(true).await;
}
#[tokio::test]
async fn sqlite_fallback_account_owner_retains_the_peer_after_original_error() {
    sqlite(false).await;
}
#[tokio::test]
async fn sqlite_native_account_owner_retains_the_peer_after_original_error() {
    sqlite(true).await;
}
