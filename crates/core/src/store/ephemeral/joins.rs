//! Native joins retain child row references selected by the original raw query.

use super::account_joins::{native_relation, user_value};
use super::rows::RecordSource;
use super::rows::RowRef;
use super::sessions::{session_token_matches, session_tokens_match};
use super::*;
use crate::session::SessionData;
use crate::store::JoinValue;
use crate::store::schema::resolve_field_name;
use crate::user_fields::{
    UserFieldConfig, project_adapter_value, project_owned_source_fields_batches_then,
};
use futures_util::future::BoxFuture;

type UserRef = RowRef<UserView>;
type UserProjection = (UserRef, bool, FieldMap);
type SessionSnapshot = (SessionView, Option<SessionData<JoinValue<UserView>>>);

fn read_user_field(
    runtime: &crate::plugin_runtime::ModelFields,
    (source, started, _): &mut UserProjection,
    name: &str,
    field: &UserFieldConfig,
) -> AuthResult<Option<Value>> {
    if !*started {
        runtime.begin_id_output(crate::store::schema::EntityRole::User)?;
        *started = true;
    }
    let physical = resolve_field_name(field.field_name.as_deref(), name);
    source.field(physical)
}

fn apply_user_field<'a>(
    (_, _, output): &'a mut UserProjection,
    name: &'a str,
    field: &'a UserFieldConfig,
    value: Option<Value>,
) -> BoxFuture<'a, AuthResult<()>> {
    Box::pin(async move {
        let value = if name == "id" {
            EphemeralStore::project_id(&crate::SchemaValue::from_field(value.unwrap_or_default()))?
                .into_field_value()
        } else {
            project_adapter_value(
                value.unwrap_or_default(),
                field,
                field.references_id(),
                true,
            )
            .await?
        };
        let _ = output.insert(name.to_owned(), value);
        Ok(())
    })
}

impl EphemeralStore {
    pub(super) async fn output_user_refs(&self, users: Vec<UserRef>) -> AuthResult<Vec<UserView>> {
        self.output_user_refs_batches_then(users, |ready| std::future::ready(Ok(ready)))
            .await
    }

    pub(super) async fn output_user_refs_batches_then<R: Send + 'static, F>(
        &self,
        users: Vec<UserRef>,
        complete: impl Fn(Vec<(usize, UserView)>) -> F + Send + Sync + 'static,
    ) -> AuthResult<Vec<R>>
    where
        F: std::future::Future<Output = AuthResult<Vec<(usize, R)>>> + Send + 'static,
    {
        let fields = self.user_schema();
        let runtime = self.model_fields.clone();
        project_owned_source_fields_batches_then(
            users
                .into_iter()
                .map(|user| (user, false, FieldMap::new()))
                .collect(),
            fields.fields().clone(),
            move |row, name, field| read_user_field(&runtime, row, name, field),
            apply_user_field,
            |_, (_, _, output)| UserView::from_field_values(std::mem::take(output)),
            complete,
        )
        .await
    }

    pub(super) async fn session_user_relations(
        &self,
        token_query: Value,
        only_active: bool,
        single: bool,
    ) -> AuthResult<Vec<SessionSnapshot>> {
        use crate::store::schema::EntityRole;
        let (token_column, token_query) = self.memory_session_token_query(token_query)?;
        let native = self.config.advanced.database.joins == Some(true);
        let expiry = only_active
            .then(|| self.memory_session_field_query("expiresAt", Utc::now().into()))
            .transpose()?;
        let relation = SessionData::resolve_schema(&self.config, &self.model_fields, |_, _| false)?;
        let rows = self
            .raw(
                "session",
                if single { "findOne" } else { "findMany" },
                |state| {
                    let sessions = crate::query::paginate_memory(
                        state.sessions.try_select_refs(|session| {
                            let token_matches = if single {
                                session_token_matches(session, &token_column, &token_query)
                            } else {
                                session_tokens_match(session, &token_column, &token_query)?
                            };
                            Ok(token_matches
                                && match &expiry {
                                    Some((column, now)) => {
                                        crate::query::field_compare(
                                            session.get(column).unwrap_or(&Value::Undefined),
                                            now,
                                        )? == Some(std::cmp::Ordering::Greater)
                                    }
                                    None => true,
                                })
                        })?,
                        Some(if single {
                            1.0
                        } else {
                            self.config.advanced.database.find_many_limit()
                        }),
                        None,
                    );
                    sessions
                        .into_iter()
                        .map(|source| {
                            if !native {
                                return Ok((RecordSource::Live(source), None));
                            }
                            let session = source.shallow_fields()?;
                            let value = session.get(&relation.from).cloned().unwrap_or_default();
                            let users = native_relation(
                                state.users.select_refs(|user| {
                                    user_value(user, &relation.logical_to, &relation.to)
                                        .strict_equals(&value)
                                })?,
                                &relation,
                                self.config.advanced.database.find_many_limit(),
                                |user| user.id.field_value(),
                            )?;
                            let source = RecordSource::joined(
                                session,
                                [(
                                    self.model_fields
                                        .storage_model_name(EntityRole::User, "user")
                                        .to_owned(),
                                    users.raw_value(),
                                )],
                            );
                            Ok((source, Some(users)))
                        })
                        .collect::<AuthResult<Vec<_>>>()
                },
            )
            .await?;
        let (sessions, users): (Vec<_>, Vec<_>) = rows.into_iter().unzip();
        let fields = super::super::session_create_schema(&self.config.session, &FieldMap::new());
        let continuation = Arc::new((users, fields, relation));
        let store = self.clone();
        self.output_sessions_batches_then(sessions, move |ready| {
            let continuation = continuation.clone();
            let store = store.clone();
            async move {
                let (users, fields, relation) = continuation.as_ref();
                let mut selected = Vec::with_capacity(ready.len());
                for (index, session) in &ready {
                    let user = users.get(*index).ok_or_else(|| {
                        AuthError::internal("Session projection lost its stored join index")
                    })?;
                    selected.push(match user {
                        Some(user) => user.clone(),
                        None => {
                            store
                                .fallback_join_users(
                                    relation,
                                    (EntityRole::Session, "session", fields),
                                    &session.field_values()?,
                                )
                                .await?
                        }
                    });
                }
                let projected = store.output_user_relations(selected).await?;
                Ok(ready
                    .into_iter()
                    .zip(projected)
                    .map(|((index, session), user)| {
                        let data = SessionData {
                            session: session.clone(),
                            user,
                        };
                        (index, (session, Some(data)))
                    })
                    .collect())
            }
        })
        .await
    }
}
