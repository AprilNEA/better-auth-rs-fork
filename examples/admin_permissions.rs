//! Authorize application resources with the Admin role map.
//!
//! Run with `cargo run --example admin_permissions --features axum`.
//! The example uses an in-memory SQLite database and prints one status per request.

use axum::Router;
use axum::body::Body;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, Request, StatusCode};
use axum::routing::get;
use better_auth::plugins::admin::{AdminPermissionError, AuthorizedSession};
use better_auth::plugins::{AdminConfig, AdminPlugin, RolePermissions};
use better_auth::prelude::{CreateSession, CreateUser};
use better_auth::seaorm::sea_orm;
use better_auth::seaorm::sea_orm::entity::prelude::*;
use better_auth::seaorm::sea_orm::{ConnectionTrait, Schema};
use better_auth::seaorm::{AuthEntity, Database, DatabaseConnection, SeaOrmStore};
use better_auth::{AuthConfig, AuthSchema, BetterAuth};
use std::collections::HashMap;
use std::sync::Arc;
use tower::ServiceExt;

// The Admin plugin requires `role`, `banned`, `ban_reason`, and `ban_expires` on the user
// and `impersonated_by` on the session.
mod user {
    use super::*;

    #[derive(Clone, Debug, serde::Serialize, DeriveEntityModel, AuthEntity)]
    #[auth(role = "user")]
    #[sea_orm(table_name = "users")]
    pub struct Model {
        #[sea_orm(primary_key, auto_increment = false)]
        pub id: String,
        pub name: Option<String>,
        pub email: Option<String>,
        pub email_verified: bool,
        pub image: Option<String>,
        pub role: Option<String>,
        pub banned: bool,
        pub ban_reason: Option<String>,
        pub ban_expires: Option<DateTimeUtc>,
        pub created_at: DateTimeUtc,
        pub updated_at: DateTimeUtc,
    }

    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}

    impl ActiveModelBehavior for ActiveModel {}
}

mod session {
    use super::*;

    #[derive(Clone, Debug, serde::Serialize, DeriveEntityModel, AuthEntity)]
    #[auth(role = "session")]
    #[sea_orm(table_name = "sessions")]
    pub struct Model {
        #[sea_orm(primary_key, auto_increment = false)]
        pub id: String,
        pub expires_at: DateTimeUtc,
        pub token: String,
        pub created_at: DateTimeUtc,
        pub updated_at: DateTimeUtc,
        pub ip_address: Option<String>,
        pub user_agent: Option<String>,
        pub user_id: String,
        pub impersonated_by: Option<String>,
        pub active: bool,
    }

    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}

    impl ActiveModelBehavior for ActiveModel {}
}

mod account {
    use super::*;

    #[derive(Clone, Debug, serde::Serialize, DeriveEntityModel, AuthEntity)]
    #[auth(role = "account")]
    #[sea_orm(table_name = "accounts")]
    pub struct Model {
        #[sea_orm(primary_key, auto_increment = false)]
        pub id: String,
        pub account_id: String,
        pub provider_id: String,
        pub user_id: String,
        pub access_token: Option<String>,
        pub refresh_token: Option<String>,
        pub id_token: Option<String>,
        pub access_token_expires_at: Option<DateTimeUtc>,
        pub refresh_token_expires_at: Option<DateTimeUtc>,
        pub scope: Option<String>,
        pub password: Option<String>,
        pub created_at: DateTimeUtc,
        pub updated_at: DateTimeUtc,
    }

    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}

    impl ActiveModelBehavior for ActiveModel {}
}

mod verification {
    use super::*;

    #[derive(Clone, Debug, serde::Serialize, DeriveEntityModel, AuthEntity)]
    #[auth(role = "verification")]
    #[sea_orm(table_name = "verifications")]
    pub struct Model {
        #[sea_orm(primary_key, auto_increment = false)]
        pub id: String,
        pub identifier: String,
        pub value: String,
        pub expires_at: DateTimeUtc,
        pub created_at: DateTimeUtc,
        pub updated_at: DateTimeUtc,
    }

    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}

    impl ActiveModelBehavior for ActiveModel {}
}

pub struct AppAuthSchema;

impl AuthSchema for AppAuthSchema {
    type User = crate::user::Model;
    type Session = crate::session::Model;
    type Account = crate::account::Model;
    type Verification = crate::verification::Model;
}

type Auth = Arc<BetterAuth<AppAuthSchema>>;

/// Convert Axum headers into the header map that native Better Auth calls accept.
fn native_headers(headers: &HeaderMap) -> HashMap<String, String> {
    headers
        .iter()
        .filter_map(|(name, value)| Some((name.to_string(), value.to_str().ok()?.to_owned())))
        .collect()
}

/// Authenticate the caller from its session and require one `project` action.
async fn authorize_project(
    auth: &BetterAuth<AppAuthSchema>,
    headers: &HeaderMap,
    action: &str,
) -> Result<AuthorizedSession, StatusCode> {
    let required = HashMap::from([("project".to_owned(), vec![action.to_owned()])]);
    let checks = auth
        .admin_permissions()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    checks
        .authorize_request(&native_headers(headers), &required)
        .await
        .map_err(|error| match error {
            AdminPermissionError::Unauthenticated => StatusCode::UNAUTHORIZED,
            AdminPermissionError::Forbidden => StatusCode::FORBIDDEN,
            // Configuration, request, and storage failures are server errors, not denials.
            AdminPermissionError::PluginNotRegistered
            | AdminPermissionError::EmptyPermissions
            | AdminPermissionError::MissingSubject
            | AdminPermissionError::UserNotFound
            | AdminPermissionError::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
        })
}

async fn read_project(
    State(auth): State<Auth>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> Result<String, StatusCode> {
    let caller = authorize_project(&auth, &headers, "read").await?;
    let actor = caller.user().id.as_str().unwrap_or_default();
    Ok(format!("project {id} read by {actor}"))
}

async fn update_project(
    State(auth): State<Auth>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> Result<String, StatusCode> {
    let caller = authorize_project(&auth, &headers, "update").await?;
    // Run the business transaction and its audit record with this caller as the actor.
    let actor = caller.user().id.as_str().unwrap_or_default();
    Ok(format!("project {id} updated by {actor}"))
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut config = AuthConfig::new("example-secret-key-that-is-at-least-32-characters")
        .base_url("http://localhost:8080");
    config.session.bearer = Some(Default::default());
    let database = Database::connect("sqlite::memory:").await?;
    run_app_migrations(&database).await?;

    let admin = AdminPlugin::with_config(AdminConfig {
        default_role: "viewer".into(),
        roles: Some(HashMap::from([
            (
                "viewer".into(),
                RolePermissions::new().allow("project", ["read"]),
            ),
            (
                "editor".into(),
                RolePermissions::new().allow("project", ["read", "update"]),
            ),
        ])),
        ..Default::default()
    });
    let auth: Auth = Arc::new(
        BetterAuth::<AppAuthSchema>::new(config.clone())
            .store(SeaOrmStore::<AppAuthSchema>::new(config, database))
            .plugin(admin)
            .build()
            .await?,
    );
    let app = Router::new()
        .route("/projects/{id}", get(read_project).patch(update_project))
        .with_state(auth.clone());

    for role in ["viewer", "editor"] {
        let token = seed_session(&auth, role).await?;
        for method in ["GET", "PATCH"] {
            let request = Request::builder()
                .method(method)
                .uri("/projects/demo")
                .header("authorization", format!("Bearer {token}"))
                .body(Body::empty())?;
            let status = app.clone().oneshot(request).await?.status();
            println!("{role} {method} /projects/demo -> {status}");
        }
    }
    let anonymous = Request::builder()
        .uri("/projects/demo")
        .body(Body::empty())?;
    println!(
        "anonymous GET /projects/demo -> {}",
        app.oneshot(anonymous).await?.status()
    );
    Ok(())
}

/// Create a user with `role` and return a bearer token for a new session.
async fn seed_session(
    auth: &BetterAuth<AppAuthSchema>,
    role: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    let user = auth
        .store()
        .create_user(
            CreateUser::new()
                .with_email(format!("{role}@example.com"))
                .with_name(role)
                .with_role(role),
        )
        .await?;
    let session = auth
        .store()
        .create_session(CreateSession {
            additional_fields: Default::default(),
            user_id: user.id,
            expires_at: (chrono::Utc::now() + chrono::Duration::hours(1)).into(),
            ip_address: None,
            user_agent: None,
            impersonated_by: None,
            active_organization_id: None,
        })
        .await?;
    Ok(session.token)
}

async fn run_app_migrations(database: &DatabaseConnection) -> Result<(), sea_orm::DbErr> {
    let schema = Schema::new(database.get_database_backend());
    for statement in [
        schema.create_table_from_entity(user::Entity).to_owned(),
        schema.create_table_from_entity(session::Entity).to_owned(),
        schema.create_table_from_entity(account::Entity).to_owned(),
        schema
            .create_table_from_entity(verification::Entity)
            .to_owned(),
    ] {
        let _ = database.execute(&statement).await?;
    }
    Ok(())
}
