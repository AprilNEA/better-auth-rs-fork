use super::*;
use better_auth_core::user_fields::{UserFieldFactory, UserFieldType};
use better_auth_core::{SchemaValue, UpdateAccount};

const UPDATED: f64 = 2_000_000_000_000.0;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Mutation {
    None,
    Provider,
    Replacement,
}

struct MutatingHasher<S: AuthSchema> {
    state: Arc<State>,
    database: Arc<dyn AuthStore<S>>,
    account_id: FieldValue,
    user_id: SchemaValue<String>,
    mutation: Mutation,
    after_callback: Mutex<Option<FieldMap>>,
}

#[async_trait]
impl<S: AuthSchema> PasswordHasher for MutatingHasher<S> {
    async fn hash(&self, password: &str) -> AuthResult<String> {
        self.state.hash(password).await
    }

    async fn verify(&self, _: &str, _: &str) -> AuthResult<bool> {
        Err(AuthError::internal(
            "The native verifier must receive the original hash",
        ))
    }

    async fn verify_native(&self, hash: &FieldValue, password: &str) -> AuthResult<FieldValue> {
        let result = self.state.verify_native(hash, password).await?;
        match self.mutation {
            Mutation::None => {}
            Mutation::Provider => {
                let _ = self
                    .database
                    .update_account_by_id_value(
                        &self.account_id,
                        UpdateAccount {
                            provider_id: "changed-provider".into(),
                            ..Default::default()
                        },
                    )
                    .await?;
            }
            Mutation::Replacement => {
                self.database.delete_account_value(&self.account_id).await?;
                let _ = self
                    .database
                    .create_account(CreateAccount {
                        user_id: self.user_id.clone(),
                        account_id: self.user_id.clone(),
                        provider_id: "credential".into(),
                        password: Some("replacement-hash".to_owned()).into(),
                        ..Default::default()
                    })
                    .await?;
            }
        }
        let records = self
            .database
            .get_user_accounts(self.user_id.typed()?)
            .await?;
        assert_eq!(records.len(), 1);
        *self.after_callback.lock().unwrap() = records.into_iter().next().map(FieldMap::from);
        Ok(result)
    }
}

async fn check_selected_account<S: AuthSchema>(
    database: Arc<dyn AuthStore<S>>,
    mutation: Mutation,
) -> AuthResult<()> {
    let mut config = test_helpers::create_test_config().disable_session_refresh(true);
    let _ = config.account.additional_fields.insert(
        "updatedAt".into(),
        UserFieldConfig {
            field_type: UserFieldType::Date,
            required: Some(true),
            on_update: Some(UserFieldFactory::new(|| {
                Ok(better_auth_core::FieldDate::from_milliseconds(UPDATED).into())
            })),
            ..Default::default()
        },
    );
    let raw =
        test_helpers::initialize_test_context(Arc::new(config.clone()), database.clone(), &[])
            .await?;
    let user = raw
        .database
        .create_user(
            CreateUser::new()
                .with_name("Owner")
                .with_email("owner@selected-account.test"),
        )
        .await?;
    let account = raw
        .database
        .create_account(CreateAccount {
            user_id: user.id.clone(),
            account_id: user.id.clone(),
            provider_id: "credential".into(),
            password: Some("stored-hash".to_owned()).into(),
            ..Default::default()
        })
        .await?;
    let session =
        test_helpers::create_session(&raw, user.id.typed()?.clone(), chrono::Duration::hours(1))
            .await;
    let sessions = raw
        .database
        .get_user_sessions(user.id.typed()?)
        .await?
        .into_iter()
        .map(FieldMap::from)
        .collect::<Vec<_>>();
    let state = Arc::new(State::default());
    *state.projected.lock().unwrap() = native_hash();
    *state.result.lock().unwrap() = true.into();
    let hasher = Arc::new(MutatingHasher {
        state: state.clone(),
        database: raw.database.clone(),
        account_id: account.id.field_value(),
        user_id: user.id.clone(),
        mutation,
        after_callback: Mutex::new(None),
    });
    let output_state = state.clone();
    let _ =
        config.account.additional_fields.insert(
            "password".into(),
            UserFieldConfig {
                required: Some(false),
                returned: Some(false),
                transform: Some(FieldTransforms {
                    input: None,
                    output: Some(UserFieldTransform::new(move |value| {
                        output_state.events.lock().unwrap().push(
                            if value == "stored-hash".into() {
                                "projection"
                            } else {
                                assert_eq!(value, "new-hash".into());
                                "projection-updated"
                            },
                        );
                        Ok(output_state.projected.lock().unwrap().clone())
                    })),
                }),
                ..Default::default()
            },
        );
    let email = EmailPasswordPlugin::new().password_hasher(hasher.clone());
    let password = PasswordManagementPlugin::new();
    let context =
        test_helpers::initialize_test_context(Arc::new(config), database, &[&email, &password])
            .await?;
    let expected_user = serde_json::to_value(context.user_view(&user).await?)?;
    let req = test_helpers::create_auth_json_request_no_query(
        HttpMethod::Post,
        "/change-password",
        Some(session.token.typed()?),
        Some(json!({"currentPassword":PASSWORD,"newPassword":PASSWORD})),
    );
    let response = password
        .on_request(&req, &context.initialize_request_context().await?)
        .await?
        .unwrap();
    assert_eq!(
        response.body.json()?,
        Some(json!({"token":null,"user":expected_user}))
    );
    assert_eq!(
        *state.events.lock().unwrap(),
        if mutation == Mutation::Replacement {
            vec!["projection", "hash", "verify"]
        } else {
            vec!["projection", "hash", "verify", "projection-updated"]
        }
    );
    let mut expected = hasher.after_callback.lock().unwrap().take().unwrap();
    if mutation != Mutation::Replacement {
        let _ = expected.insert("password".into(), "new-hash".into());
        let _ = expected.insert(
            "updatedAt".into(),
            better_auth_core::FieldDate::from_milliseconds(UPDATED).into(),
        );
    } else {
        assert_ne!(expected.get("id"), Some(&account.id.field_value()));
    }
    assert_eq!(
        raw.database
            .get_user_accounts(user.id.typed()?)
            .await?
            .into_iter()
            .map(FieldMap::from)
            .collect::<Vec<_>>(),
        vec![expected]
    );
    assert_eq!(
        raw.database
            .get_user_sessions(user.id.typed()?)
            .await?
            .into_iter()
            .map(FieldMap::from)
            .collect::<Vec<_>>(),
        sessions
    );
    assert_eq!(
        raw.database
            .get_user_by_id(user.id.typed()?)
            .await?
            .unwrap(),
        user
    );
    Ok(())
}

#[tokio::test]
async fn change_password_updates_the_first_account_after_verifier_mutation() -> AuthResult<()> {
    for mutation in [Mutation::None, Mutation::Provider, Mutation::Replacement] {
        let memory: Arc<dyn AuthStore<StatelessSchema>> = Arc::new(EphemeralStore::default());
        check_selected_account(memory, mutation).await?;
        check_selected_account(test_helpers::create_test_database().await, mutation).await?;
    }
    Ok(())
}
