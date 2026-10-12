/// Shared plugin storage assertions for generated catalog tests.
#[path = "tests/plugin_catalog_rows.rs"]
pub mod plugin_catalog_rows;
/// Shared server index assertions for generated catalog tests.
#[path = "tests/server_catalog_indexes.rs"]
pub mod server_catalog_indexes;
/// Shared server setup and assertions for generated catalog tests.
#[path = "tests/server_catalog_support.rs"]
pub mod server_catalog_support;
/// Shared SQLite storage assertions for generated catalog tests.
#[path = "tests/sqlite_catalog.rs"]
pub mod sqlite_catalog;

#[cfg(test)]
mod tests {
    mod device_intervals;
    mod http_request;
    mod reference_fields;

    use std::sync::Arc;

    use axum::{Json, Router, http::StatusCode, routing::get};
    use better_auth::integrations::axum::{AxumIntegration, CurrentSession};
    use better_auth::plugins::{
        ApiKeyPlugin, EmailPasswordPlugin, SessionManagementPlugin, TwoFactorPlugin,
    };
    use better_auth::seaorm::sea_orm::ConnectionTrait;
    use better_auth::seaorm::{Database, SeaOrmStore};
    use better_auth::{AuthConfig, BetterAuth};
    use http_request::request;
    use serde_json::{Value, json};

    mod generated {
        include!(env!("BETTER_AUTH_GENERATED_SCHEMA"));
    }

    async fn protected(session: CurrentSession<generated::AppAuthSchema>) -> Json<Value> {
        Json(json!({"userId": session.user.id}))
    }

    #[tokio::test]
    async fn generated_legacy_user_defaults_do_not_activate_plugin_fields() {
        use better_auth::seaorm::sea_orm::EntityTrait;
        use better_auth::{__private_core::store::UserStore, FieldMap, prelude::CreateUser};

        let database = Database::connect("sqlite::memory:").await.unwrap();
        generated::create_auth_tables(&database).await.unwrap();
        let store =
            SeaOrmStore::<generated::AppAuthSchema>::new(AuthConfig::default(), database.clone());
        let user = store
            .create_user(CreateUser {
                banned: Some(true),
                metadata: Some(FieldMap::from([("inactive".into(), true.into())]).into()),
                additional_fields: FieldMap::from([("twoFactorEnabled".into(), true.into())]),
                ..CreateUser::new()
                    .with_name("Inactive plugins")
                    .with_email("inactive@example.com")
            })
            .await
            .unwrap();
        assert!(user.banned.is_undefined());
        assert!(user.two_factor_enabled.is_undefined());
        assert!(user.metadata.is_undefined());
        let stored = generated::user::Entity::find_by_id(user.id.typed().unwrap())
            .one(&database)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(stored.banned, None);
        assert!(!stored.two_factor_enabled);
        let (catalog, _) = crate::sqlite_catalog::observe(&database, "user", "Missing User table")
            .await
            .unwrap();
        assert!(
            catalog["columns"]
                .as_array()
                .unwrap()
                .iter()
                .all(|column| column["name"] != "metadata")
        );
    }

    #[tokio::test]
    async fn generated_schema_supports_authentication_and_two_factor() {
        let database = Database::connect("sqlite::memory:").await.unwrap();
        generated::create_auth_tables(&database).await.unwrap();
        assert!(
            generated::create_auth_tables(&database).await.is_err(),
            "the initial scaffold must not silently accept an existing schema"
        );
        let mut config = AuthConfig::new("consumer-test-secret-at-least-32-characters")
            .base_url("http://localhost:3000");
        config.session.bearer = Some(Default::default());
        let auth = Arc::new(
            BetterAuth::<generated::AppAuthSchema>::new(config.clone())
                .store(
                    SeaOrmStore::<generated::AppAuthSchema>::new(config, database.clone())
                        .with_organization_schema::<generated::AppOrganizationSchema>()
                        .with_plugin_schema::<generated::AppPluginSchema>(),
                )
                .plugin(EmailPasswordPlugin::new().enable_signup(true))
                .plugin(SessionManagementPlugin::new())
                .plugin(TwoFactorPlugin::new())
                .plugin(ApiKeyPlugin::builder().build())
                .build()
                .await
                .unwrap(),
        );
        let router = Router::new()
            .nest("/auth", auth.clone().axum_router())
            .route("/protected", get(protected))
            .with_state(auth);
        assert_eq!(
            request(&router, "/protected", None, None).await.0,
            StatusCode::UNAUTHORIZED
        );
        let credentials = json!({"email": "consumer@example.com", "password": "test-password-123", "name": "Consumer"});
        let (status, signup) = request(
            &router,
            "/auth/sign-up/email",
            Some(credentials.clone()),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{signup}");
        let (status, signin) = request(
            &router,
            "/auth/sign-in/email",
            Some(credentials.clone()),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{signin}");
        let token = signin["token"].as_str().unwrap();
        let (status, protected) = request(&router, "/protected", None, Some(token)).await;
        assert_eq!(status, StatusCode::OK, "{protected}");
        assert_eq!(protected["userId"], signup["user"]["id"]);

        let (status, api_key) = request(
            &router,
            "/auth/api-key/create",
            Some(json!({"name": "consumer key"})),
            Some(token),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{api_key}");
        assert_eq!(api_key["referenceId"], signup["user"]["id"]);
        assert_eq!(api_key["configId"], "default");

        let (status, enabled) = request(
            &router,
            "/auth/two-factor/enable",
            Some(json!({"password": "test-password-123", "method": "totp"})),
            Some(token),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{enabled}");
        let totp = totp_rs::TOTP::from_url(enabled["totpURI"].as_str().unwrap()).unwrap();
        let (status, verified) = request(
            &router,
            "/auth/two-factor/verify-totp",
            Some(json!({"code": totp.generate_current().unwrap()})),
            Some(token),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{verified}");
        let (status, challenge) =
            request(&router, "/auth/sign-in/email", Some(credentials), None).await;
        assert_eq!(status, StatusCode::OK, "{challenge}");
        assert_eq!(challenge["twoFactorRedirect"], true, "{challenge}");
        assert!(challenge.get("token").is_none());

        // The database must enforce invariants when concurrent requests bypass prechecks.
        for (statement, expected) in [
            (
                "INSERT INTO user (id, name, email, emailVerified, image, createdAt, updatedAt, role, banned, banReason, banExpires, two_factor_enabled, username, displayUsername) SELECT 'duplicate', name, email, emailVerified, image, createdAt, updatedAt, role, banned, banReason, banExpires, two_factor_enabled, username, displayUsername FROM user LIMIT 1",
                "UNIQUE constraint failed: user.email",
            ),
            (
                "UPDATE session SET userId = 'missing-user'",
                "FOREIGN KEY constraint failed",
            ),
            (
                "INSERT INTO two_factor SELECT 'duplicate', secret, backup_codes, user_id, verified, failed_verification_count, locked_until, created_at, updated_at FROM two_factor LIMIT 1",
                "UNIQUE constraint failed: two_factor.user_id",
            ),
        ] {
            let error = database.execute_unprepared(statement).await.unwrap_err();
            assert!(
                error.to_string().contains(expected),
                "unexpected constraint error: {error}"
            );
        }
        database.execute_unprepared("INSERT INTO account SELECT 'duplicate', accountId, providerId, userId, accessToken, refreshToken, idToken, accessTokenExpiresAt, refreshTokenExpiresAt, scope, password, createdAt, updatedAt FROM account LIMIT 1").await.unwrap();
        let store =
            SeaOrmStore::<generated::AppAuthSchema>::new(AuthConfig::default(), database.clone());
        let store: &dyn better_auth::store::AuthStore<generated::AppAuthSchema> = &store;
        let error = store
            .get_account("credential", signup["user"]["id"].as_str().unwrap())
            .await
            .unwrap_err();
        assert_eq!(
            error.instrumentation_message().unwrap(),
            "Multiple accounts match the same accountId for provider \"credential\". Resolve duplicate account identities before continuing."
        );
        database.close().await.unwrap();
    }
}
