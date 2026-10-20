//! Typed Admin permission checks reuse the registered role map for application resources.
#![allow(
    clippy::panic_in_result_fn,
    reason = "Test assertions fail the test; Result propagates setup and API errors."
)]

use std::collections::HashMap;
use std::error::Error;
use std::sync::Arc;

use better_auth::config::CookieCacheConfig;
use better_auth::plugins::admin::AdminPermissionError;
use better_auth::plugins::{
    AdminConfig, AdminPlugin, EmailPasswordPlugin, RolePermissions, SessionManagementPlugin,
};
use better_auth::prelude::{
    AuthRequest, AuthResponse, CreateSession, CreateUser, HttpMethod, UpdateUser, UserView,
};
use better_auth::store::MemoryCacheAdapter;
use better_auth::{AuthConfig, BetterAuth};
use better_auth_seaorm::{Database, SeaOrmStore};
use chrono::{Duration, Utc};
use serde_json::{Value, json};

type TestSchema = better_auth_seaorm::store::__private_test_support::bundled_schema::BundledSchema;
type TestResult = Result<(), Box<dyn Error>>;

const ORIGIN: &str = "http://localhost:3000";
const OWNER_ID: &str = "owner-user";

#[derive(Clone, Copy, PartialEq)]
enum Storage {
    Database,
    Secondary,
}

fn permissions(entries: &[(&str, &[&str])]) -> HashMap<String, Vec<String>> {
    entries
        .iter()
        .map(|(resource, actions)| {
            let actions = actions.iter().map(|action| (*action).to_owned()).collect();
            ((*resource).to_owned(), actions)
        })
        .collect()
}

/// `viewer` reads projects, `editor` updates them, and `billing` reads invoices.
fn project_admin() -> AdminPlugin {
    AdminPlugin::with_config(AdminConfig {
        default_role: "viewer".into(),
        admin_user_ids: Some(vec![OWNER_ID.into()]),
        roles: Some(HashMap::from([
            (
                "viewer".into(),
                RolePermissions::new().allow("project", ["read"]),
            ),
            (
                "editor".into(),
                RolePermissions::new().allow("project", ["read", "update"]),
            ),
            (
                "billing".into(),
                RolePermissions::new().allow("invoice", ["read"]),
            ),
        ])),
        ..Default::default()
    })
}

async fn build_auth(
    admin: Option<AdminPlugin>,
    storage: Storage,
    cookie_cache: bool,
) -> Result<BetterAuth<TestSchema>, Box<dyn Error>> {
    let database = Database::connect("sqlite::memory:").await?;
    better_auth_seaorm::store::__private_test_support::migrator::run_migrations(&database).await?;
    let mut config = AuthConfig::new("test-secret-key-that-is-at-least-32-characters-long")
        .base_url(ORIGIN)
        .password_min_length(8);
    config.session.bearer = Some(Default::default());
    if cookie_cache {
        config.session.cookie_cache = Some(CookieCacheConfig {
            enabled: Some(true),
            max_age: Some(Duration::minutes(5)),
            ..Default::default()
        });
    }
    let store = SeaOrmStore::<TestSchema>::new(config.clone(), database);
    let mut builder = BetterAuth::<TestSchema>::new(config)
        .store(store)
        .plugin(EmailPasswordPlugin::new())
        .plugin(SessionManagementPlugin::new());
    if storage == Storage::Secondary {
        builder = builder.secondary_storage(Arc::new(MemoryCacheAdapter::new()));
    }
    if let Some(admin) = admin {
        builder = builder.plugin(admin);
    }
    Ok(builder.build().await?)
}

async fn create_user(
    auth: &BetterAuth<TestSchema>,
    email: &str,
    id: Option<&str>,
    role: Option<&str>,
) -> Result<UserView, Box<dyn Error>> {
    let mut user = CreateUser::new().with_email(email).with_name("Fixture");
    if let Some(role) = role {
        user = user.with_role(role);
    }
    user.id = id.map(str::to_owned);
    Ok(auth.store().create_user(user).await?)
}

/// Create a session in the configured store and return bearer headers for it.
async fn bearer_headers(
    auth: &BetterAuth<TestSchema>,
    user: &UserView,
    expires_in: Duration,
) -> Result<HashMap<String, String>, Box<dyn Error>> {
    let session = auth
        .store()
        .create_session(CreateSession {
            additional_fields: Default::default(),
            user_id: user.id.clone(),
            expires_at: (Utc::now() + expires_in).into(),
            ip_address: None,
            user_agent: None,
            impersonated_by: None,
            active_organization_id: None,
        })
        .await?;
    // Mixed-case names exercise the same normalization as framework requests.
    Ok(HashMap::from([(
        "Authorization".into(),
        format!("Bearer {}", session.token),
    )]))
}

async fn set_role(auth: &BetterAuth<TestSchema>, user: &UserView, role: &str) -> TestResult {
    let _ = auth
        .store()
        .update_user(
            user.id.as_str().ok_or("fixture user ID is a string")?,
            UpdateUser {
                role: Some(role.into()),
                ..Default::default()
            },
        )
        .await?;
    Ok(())
}

fn request(method: HttpMethod, path: &str, headers: &HashMap<String, String>) -> AuthRequest {
    let mut request = AuthRequest::new(method, path);
    for (name, value) in headers {
        let _ = request
            .headers
            .insert(name.to_ascii_lowercase(), value.clone());
    }
    let _ = request.headers.insert("origin".into(), ORIGIN.into());
    request
}

fn json_request(path: &str, body: &Value, headers: &HashMap<String, String>) -> AuthRequest {
    let mut request = request(HttpMethod::Post, path, headers);
    request.body = Some(body.to_string().into_bytes());
    let _ = request
        .headers
        .insert("content-type".into(), "application/json".into());
    request
}

fn response_json(response: &AuthResponse) -> Result<Value, Box<dyn Error>> {
    Ok(serde_json::from_slice(&response.body.bytes()?)?)
}

/// Join the non-empty `Set-Cookie` values into one `Cookie` request header.
fn cookie_headers(response: &AuthResponse) -> HashMap<String, String> {
    let cookies = response
        .headers
        .get_all("Set-Cookie")
        .filter_map(|header| header.split(';').next())
        .filter(|pair| {
            pair.split_once('=')
                .is_some_and(|(_, value)| !value.is_empty())
        })
        .collect::<Vec<_>>()
        .join("; ");
    HashMap::from([("cookie".into(), cookies)])
}

// Rust-specific surface: the typed accessor reports a missing plugin instead of denying access.
#[tokio::test]
async fn missing_admin_plugin_is_a_typed_error() -> TestResult {
    let auth = build_auth(None, Storage::Database, false).await?;
    assert!(matches!(
        auth.admin_permissions(),
        Err(AdminPermissionError::PluginNotRegistered)
    ));
    Ok(())
}

// Upstream reference: packages/better-auth/src/plugins/admin/has-permission.ts
// Upstream reference: packages/better-auth/src/plugins/access/access.ts
#[tokio::test]
async fn role_checks_use_the_registered_custom_role_map() -> TestResult {
    let auth = build_auth(Some(project_admin()), Storage::Database, false).await?;
    let checks = auth.admin_permissions()?;
    let read = permissions(&[("project", &["read"])]);
    let update = permissions(&[("project", &["update"])]);
    let read_update = permissions(&[("project", &["read", "update"])]);

    assert!(checks.role_has_permission("viewer", &read)?);
    assert!(!checks.role_has_permission("viewer", &update)?);
    assert!(!checks.role_has_permission("viewer", &read_update)?);
    assert!(checks.role_has_permission("editor", &read_update)?);
    // Unknown roles, resources, and actions grant nothing.
    assert!(!checks.role_has_permission("ghost", &read)?);
    assert!(!checks.role_has_permission("editor", &permissions(&[("ticket", &["read"])]))?);
    assert!(!checks.role_has_permission("editor", &permissions(&[("project", &["delete"])]))?);
    // Custom roles replace the built-in role map.
    assert!(!checks.role_has_permission("admin", &permissions(&[("user", &["list"])]))?);
    // One listed role must grant every requested action; roles are not merged.
    assert!(checks.role_has_permission("viewer,editor", &update)?);
    let project_and_invoice = permissions(&[("project", &["read"]), ("invoice", &["read"])]);
    assert!(!checks.role_has_permission("viewer,billing", &project_and_invoice)?);
    // Role names are split on commas without trimming.
    assert!(!checks.role_has_permission("viewer, editor", &update)?);
    // Explicit role checks never match `admin_user_ids`.
    assert!(!checks.role_has_permission(OWNER_ID, &read)?);
    Ok(())
}

// Upstream reference: packages/better-auth/src/plugins/admin/access/statement.ts
#[tokio::test]
async fn role_checks_use_built_in_roles_without_custom_roles() -> TestResult {
    let auth = build_auth(Some(AdminPlugin::new()), Storage::Database, false).await?;
    let checks = auth.admin_permissions()?;
    assert!(checks.role_has_permission("admin", &permissions(&[("user", &["list"])]))?);
    assert!(!checks.role_has_permission("user", &permissions(&[("user", &["list"])]))?);
    assert!(!checks.role_has_permission("admin", &permissions(&[("project", &["read"])]))?);
    Ok(())
}

// Rust-specific surface: typed checks reject empty requests and empty subjects as errors.
#[tokio::test]
async fn empty_requests_and_subjects_are_errors() -> TestResult {
    let auth = build_auth(Some(project_admin()), Storage::Database, false).await?;
    let owner = create_user(&auth, "owner@example.com", Some(OWNER_ID), None).await?;
    let headers = bearer_headers(&auth, &owner, Duration::hours(1)).await?;
    let checks = auth.admin_permissions()?;
    let read = permissions(&[("project", &["read"])]);

    for empty in [HashMap::new(), permissions(&[("project", &[])])] {
        assert!(matches!(
            checks.role_has_permission("editor", &empty),
            Err(AdminPermissionError::EmptyPermissions)
        ));
        // `admin_user_ids` would grant an empty request in the HTTP endpoint.
        assert!(matches!(
            checks.user_has_permission(OWNER_ID, &empty).await,
            Err(AdminPermissionError::EmptyPermissions)
        ));
        assert!(matches!(
            checks.authorize_request(&headers, &empty).await,
            Err(AdminPermissionError::EmptyPermissions)
        ));
    }
    assert!(matches!(
        checks.role_has_permission("", &read),
        Err(AdminPermissionError::MissingSubject)
    ));
    assert!(matches!(
        checks.user_has_permission("", &read).await,
        Err(AdminPermissionError::MissingSubject)
    ));
    Ok(())
}

// Upstream reference: packages/better-auth/src/plugins/admin/routes.ts
#[tokio::test]
async fn user_checks_read_the_current_stored_role() -> TestResult {
    let auth = build_auth(Some(project_admin()), Storage::Database, false).await?;
    let checks = auth.admin_permissions()?;
    let update = permissions(&[("project", &["update"])]);
    let read = permissions(&[("project", &["read"])]);

    let editor = create_user(&auth, "editor@example.com", None, Some("editor")).await?;
    let editor_id = editor.id.as_str().ok_or("fixture user ID is a string")?;
    assert!(checks.user_has_permission(editor_id, &update).await?);
    set_role(&auth, &editor, "viewer").await?;
    assert!(!checks.user_has_permission(editor_id, &update).await?);
    assert!(checks.user_has_permission(editor_id, &read).await?);

    // A user without a role uses the configured default role.
    let plain = create_user(&auth, "plain@example.com", None, None).await?;
    let plain_id = plain.id.as_str().ok_or("fixture user ID is a string")?;
    assert!(checks.user_has_permission(plain_id, &read).await?);
    assert!(!checks.user_has_permission(plain_id, &update).await?);

    // A user listed in `admin_user_ids` passes even for resources no role defines.
    let _owner = create_user(&auth, "owner@example.com", Some(OWNER_ID), None).await?;
    let unknown = permissions(&[("ticket", &["delete"])]);
    assert!(checks.user_has_permission(OWNER_ID, &unknown).await?);

    assert!(matches!(
        checks.user_has_permission("missing-user", &read).await,
        Err(AdminPermissionError::UserNotFound)
    ));
    Ok(())
}

// Rust-specific surface: the caller comes from the framework session, never from client claims.
#[tokio::test]
async fn request_checks_authenticate_the_caller() -> TestResult {
    let auth = build_auth(Some(project_admin()), Storage::Database, false).await?;
    let checks = auth.admin_permissions()?;
    let update = permissions(&[("project", &["update"])]);

    let editor = create_user(&auth, "editor@example.com", None, Some("editor")).await?;
    let viewer = create_user(&auth, "viewer@example.com", None, Some("viewer")).await?;
    let owner = create_user(&auth, "owner@example.com", Some(OWNER_ID), Some("viewer")).await?;
    let editor_headers = bearer_headers(&auth, &editor, Duration::hours(1)).await?;

    let authorized = checks.authorize_request(&editor_headers, &update).await?;
    assert_eq!(authorized.user().id, editor.id);
    assert_eq!(authorized.session().user_id, editor.id);

    let mut viewer_headers = bearer_headers(&auth, &viewer, Duration::hours(1)).await?;
    let _ = viewer_headers.insert("x-user-role".into(), "editor".into());
    assert!(matches!(
        checks.authorize_request(&viewer_headers, &update).await,
        Err(AdminPermissionError::Forbidden)
    ));

    let owner_headers = bearer_headers(&auth, &owner, Duration::hours(1)).await?;
    let owner_session = checks.authorize_request(&owner_headers, &update).await?;
    assert_eq!(owner_session.user().id, owner.id);

    let expired = bearer_headers(&auth, &editor, Duration::hours(-1)).await?;
    let invalid = HashMap::from([("authorization".into(), "Bearer not-a-session".into())]);
    for headers in [HashMap::new(), invalid, expired] {
        assert!(matches!(
            checks.authorize_request(&headers, &update).await,
            Err(AdminPermissionError::Unauthenticated)
        ));
    }
    Ok(())
}

// Rust-specific surface: each check rereads the session store after revocation or downgrade.
#[tokio::test]
async fn request_checks_observe_revocation_and_role_downgrade() -> TestResult {
    for storage in [Storage::Database, Storage::Secondary] {
        let auth = build_auth(Some(project_admin()), storage, false).await?;
        let checks = auth.admin_permissions()?;
        let update = permissions(&[("project", &["update"])]);
        let editor = create_user(&auth, "editor@example.com", None, Some("editor")).await?;
        let headers = bearer_headers(&auth, &editor, Duration::hours(1)).await?;

        let _ = checks.authorize_request(&headers, &update).await?;
        set_role(&auth, &editor, "viewer").await?;
        assert!(matches!(
            checks.authorize_request(&headers, &update).await,
            Err(AdminPermissionError::Forbidden)
        ));

        set_role(&auth, &editor, "editor").await?;
        let _ = checks.authorize_request(&headers, &update).await?;
        let token = headers
            .get("Authorization")
            .and_then(|value| value.strip_prefix("Bearer "))
            .ok_or("fixture bearer header")?;
        auth.session_manager().delete_session(token).await?;
        assert!(matches!(
            checks.authorize_request(&headers, &update).await,
            Err(AdminPermissionError::Unauthenticated)
        ));
    }
    Ok(())
}

// Rust-specific surface: a valid cookie cache snapshot never authorizes a revoked or downgraded user.
#[tokio::test]
async fn request_checks_bypass_the_cookie_cache() -> TestResult {
    let auth = build_auth(Some(project_admin()), Storage::Database, true).await?;
    let checks = auth.admin_permissions()?;
    let update = permissions(&[("project", &["update"])]);
    let credentials = json!({ "email": "cached@example.com", "password": "password123" });
    let mut sign_up = credentials.clone();
    if let Some(body) = sign_up.as_object_mut() {
        let _ = body.insert("name".into(), "Cached".into());
    }
    let response = auth
        .handle_request(json_request("/sign-up/email", &sign_up, &HashMap::new()))
        .await?;
    assert_eq!(response.status, 200);
    let user = auth
        .store()
        .get_user_by_email("cached@example.com")
        .await?
        .ok_or("signed-up user")?;
    set_role(&auth, &user, "editor").await?;
    let response = auth
        .handle_request(json_request(
            "/sign-in/email",
            &credentials,
            &HashMap::new(),
        ))
        .await?;
    assert_eq!(response.status, 200);
    let cookies = cookie_headers(&response);
    let _ = checks.authorize_request(&cookies, &update).await?;

    set_role(&auth, &user, "viewer").await?;
    let cached = auth
        .handle_request(request(HttpMethod::Get, "/get-session", &cookies))
        .await?;
    let raw = String::from_utf8_lossy(&cached.body.bytes()?).into_owned();
    assert_eq!(
        cached.status, 200,
        "get-session body: {raw:?}, cookies: {cookies:?}"
    );
    let cached = response_json(&cached)?;
    let cached_role = cached.get("user").and_then(|user| user.get("role"));
    assert_eq!(
        cached_role,
        Some(&json!("editor")),
        "cookie cache keeps the old role"
    );
    assert!(matches!(
        checks.authorize_request(&cookies, &update).await,
        Err(AdminPermissionError::Forbidden)
    ));

    set_role(&auth, &user, "editor").await?;
    let token = auth
        .session_manager()
        .extract_session_token(&request(HttpMethod::Get, "/get-session", &cookies))
        .ok_or("signed session cookie")?;
    auth.session_manager().delete_session(&token).await?;
    assert!(matches!(
        checks.authorize_request(&cookies, &update).await,
        Err(AdminPermissionError::Unauthenticated)
    ));
    Ok(())
}

// Upstream reference: packages/better-auth/src/plugins/admin/routes.ts
// Upstream reference: packages/better-auth/src/plugins/access/access.ts
#[tokio::test]
async fn http_endpoint_keeps_its_contract_and_matches_typed_checks() -> TestResult {
    let auth = build_auth(Some(project_admin()), Storage::Database, false).await?;
    let checks = auth.admin_permissions()?;
    let viewer = create_user(&auth, "viewer@example.com", None, Some("viewer")).await?;
    let headers = bearer_headers(&auth, &viewer, Duration::hours(1)).await?;

    for (requested, expected) in [
        (json!({ "project": ["read"] }), true),
        (json!({ "project": ["update"] }), false),
        (json!({ "ticket": ["read"] }), false),
        // Better Auth 1.7.6 rejects an empty action list.
        (json!({ "project": [] }), false),
        (json!({}), false),
    ] {
        let body = json!({ "permissions": requested });
        let response = auth
            .handle_request(json_request("/admin/has-permission", &body, &headers))
            .await?;
        assert_eq!(response.status, 200);
        assert_eq!(
            response_json(&response)?,
            json!({ "error": null, "success": expected })
        );

        let requested: HashMap<String, Vec<String>> = serde_json::from_value(requested)?;
        let typed = checks.authorize_request(&headers, &requested).await;
        match typed {
            Ok(_) => assert!(expected),
            Err(AdminPermissionError::Forbidden) => assert!(!expected),
            Err(AdminPermissionError::EmptyPermissions) => assert!(!expected),
            Err(error) => return Err(error.into()),
        }
    }

    let body = json!({ "permissions": { "project": ["read"] } });
    let response = auth
        .handle_request(json_request(
            "/admin/has-permission",
            &body,
            &HashMap::new(),
        ))
        .await?;
    assert_eq!(response.status, 401);
    Ok(())
}
