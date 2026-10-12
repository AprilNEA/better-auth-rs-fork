use super::*;
use better_auth_core::{
    session::NativeSessionData,
    store::StoreCapabilities,
    user_fields::{UserFieldFactory, UserFieldReference, UserFieldType},
};

async fn check_authoritative_user<S: AuthSchema>(
    database: Arc<dyn AuthStore<S>>,
) -> AuthResult<()> {
    for change in [false, true] {
        let mut config = test_helpers::create_test_config().disable_session_refresh(true);
        config.advanced.database.joins = Some(true);
        let _ = config.account.additional_fields.insert(
            "updatedAt".into(),
            UserFieldConfig {
                field_type: UserFieldType::Date,
                on_update: Some(UserFieldFactory::new(|| {
                    Ok(better_auth_core::FieldDate::from_milliseconds(2_000_000_000_000.0).into())
                })),
                ..Default::default()
            },
        );
        let raw =
            test_helpers::initialize_test_context(Arc::new(config.clone()), database.clone(), &[])
                .await?;
        let user = raw
            .database
            .create_user(CreateUser::new().with_name("Owner").with_email(if change {
                "change@password-session.test"
            } else {
                "verify@password-session.test"
            }))
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
        let session = test_helpers::create_session(
            &raw,
            user.id.typed()?.clone(),
            chrono::Duration::hours(1),
        )
        .await;
        let state = Arc::new(State::default());
        *state.projected.lock().unwrap() = "stored-hash".into();
        *state.result.lock().unwrap() = true.into();
        let output_state = state.clone();
        let _ = config.user.fields_mut().insert(
            "name".into(),
            UserFieldConfig {
                transform: Some(FieldTransforms {
                    input: None,
                    output: Some(UserFieldTransform::new(move |value| {
                        assert_eq!(value, "Owner".into());
                        let mut events = output_state.events.lock().unwrap();
                        assert!(!events.contains(&"user-projection"));
                        events.push("user-projection");
                        Ok(17.into())
                    })),
                }),
                ..Default::default()
            },
        );
        let output_state = state.clone();
        let user_id = user.id.field_value();
        let _ = config.session.fields_mut().insert(
            "userId".into(),
            UserFieldConfig {
                references: Some(UserFieldReference {
                    model: "user".into(),
                    field: "id".into(),
                    ..Default::default()
                }),
                transform: Some(FieldTransforms {
                    input: None,
                    output: Some(UserFieldTransform::new(move |value| {
                        assert_eq!(value, user_id);
                        output_state
                            .events
                            .lock()
                            .unwrap()
                            .push("session-owner-projection");
                        Ok("unrelated".into())
                    })),
                }),
                ..Default::default()
            },
        );
        let email = EmailPasswordPlugin::new().password_hasher(state.clone());
        let plugin = PasswordManagementPlugin::new();
        let mut context = test_helpers::initialize_test_context(
            Arc::new(config),
            database.clone(),
            &[&email, &plugin],
        )
        .await?;
        context.extensions.insert(StoreCapabilities {
            database: true,
            secondary: false,
        });
        let request = test_helpers::create_auth_json_request_no_query(
            HttpMethod::Post,
            if change {
                "/change-password"
            } else {
                "/verify-password"
            },
            Some(session.token.typed()?),
            Some(if change {
                json!({"currentPassword": PASSWORD, "newPassword": PASSWORD})
            } else {
                json!({"password": PASSWORD})
            }),
        );
        request.replace_native_session_snapshot(Some(NativeSessionData {
            session: session.clone(),
            user: FieldMap::from([("id".into(), "stale-owner".into())]).into(),
        }))?;
        let response = plugin
            .on_request(
                &request,
                context.initialize_request_context().await?.as_ref(),
            )
            .await?
            .unwrap();
        let mut expected_user = FieldMap::from(raw.user_view(&user).await?);
        let _ = expected_user.insert("name".into(), 17.into());
        assert_eq!(
            response.body.json()?,
            Some(if change {
                json!({"token":null, "user": FieldValue::from(expected_user).json()?.unwrap()})
            } else {
                json!({"status": true})
            })
        );
        assert_eq!(
            *state.events.lock().unwrap(),
            if change {
                vec![
                    "session-owner-projection",
                    "user-projection",
                    "hash",
                    "verify",
                ]
            } else {
                vec!["session-owner-projection", "user-projection", "verify"]
            }
        );
        let mut expected_account = FieldMap::from(account);
        if change {
            let _ = expected_account.insert("password".into(), "new-hash".into());
            let _ = expected_account.insert(
                "updatedAt".into(),
                better_auth_core::FieldDate::from_milliseconds(2_000_000_000_000.0).into(),
            );
        }
        assert_eq!(
            raw.database
                .get_user_accounts(user.id.typed()?)
                .await?
                .into_iter()
                .map(|account| account.field_values())
                .collect::<AuthResult<Vec<_>>>()?,
            vec![expected_account]
        );
        assert_eq!(
            FieldMap::from(
                raw.database
                    .get_session(session.token.typed()?)
                    .await?
                    .unwrap()
            ),
            FieldMap::from(session)
        );
        assert_eq!(
            raw.database
                .get_user_by_id(user.id.typed()?)
                .await?
                .unwrap(),
            user
        );
    }
    Ok(())
}

#[tokio::test]
async fn password_endpoints_consume_the_authoritative_joined_user() -> AuthResult<()> {
    let memory: Arc<dyn AuthStore<StatelessSchema>> = Arc::new(EphemeralStore::default());
    check_authoritative_user(memory).await?;
    check_authoritative_user(test_helpers::create_test_database().await).await?;
    Ok(())
}
