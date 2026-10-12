use super::*;
use better_auth_core::hooks::current_request_hook_context;

#[path = "scopes/background.rs"]
mod background;
#[path = "scopes/concurrent.rs"]
mod concurrent;
#[path = "scopes/nested.rs"]
mod nested;

fn assert_path(path: &str) {
    assert_eq!(
        current_request_hook_context()
            .expect("Endpoint scope is active")
            .path
            .as_deref(),
        Some(path)
    );
}

fn assert_root(auth: &BetterAuth<S>, store: &EphemeralStore) -> AuthResult<()> {
    assert_eq!(auth.context().base_url(), INITIAL_URL);
    assert!(auth.context().current_request_context().is_none());
    assert!(current_request_hook_context().is_none());
    assert_eq!(snapshot(store)?, empty_database());
    Ok(())
}
