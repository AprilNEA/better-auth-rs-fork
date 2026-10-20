//! Typed Admin permission checks for application code.
//!
//! These checks reuse the role map, default role, and `admin_user_ids` that the registered
//! [`AdminPlugin`](super::AdminPlugin) uses for `POST /admin/has-permission`. They add no routes.

use super::AdminConfig;
use super::access::has_permission;
use better_auth_core::wire::{SessionView, UserView};
use better_auth_core::{
    AuthContext, AuthError, AuthRequest, AuthSchema, FieldValue, HttpMethod, NativeRequest,
};
use std::collections::HashMap;

/// Failure of an Admin permission check.
///
/// A denial from a trusted query is `Ok(false)`. A denial from
/// [`AdminPermissionApi::authorize_request`] is [`AdminPermissionError::Forbidden`].
/// Infrastructure failures are never reported as a denial or as a grant.
#[derive(Debug, thiserror::Error)]
pub enum AdminPermissionError {
    /// `AdminPlugin` is not registered on this auth instance.
    #[error("AdminPlugin is not registered")]
    PluginNotRegistered,
    /// The request names no resource, or names a resource without an action.
    #[error("a permission check requires at least one action for each resource")]
    EmptyPermissions,
    /// The user ID or role to evaluate is empty.
    #[error("user id or role is required")]
    MissingSubject,
    /// No stored user has the requested ID.
    #[error("user not found")]
    UserNotFound,
    /// The headers do not identify a valid session.
    ///
    /// This covers a missing or invalid credential, and an expired, revoked, or orphaned session.
    #[error("the request is not authenticated")]
    Unauthenticated,
    /// The authenticated user's current roles do not grant every requested action.
    #[error("the authenticated user lacks the requested permissions")]
    Forbidden,
    /// The store, the configuration, or another internal operation failed.
    #[error("the permission check could not complete: {0}")]
    Internal(#[source] AuthError),
}

/// Session that passed one [`AdminPermissionApi::authorize_request`] check.
///
/// Only that method creates this value. It holds the user and session read from the store for
/// that check. Use it for the operation that requested the check. Do not cache it: a later
/// revocation or role change does not update it.
#[derive(Debug)]
pub struct AuthorizedSession {
    user: UserView,
    session: SessionView,
}

impl AuthorizedSession {
    /// User whose stored roles granted the requested permissions.
    pub fn user(&self) -> &UserView {
        &self.user
    }

    /// Session that authenticated the request.
    pub fn session(&self) -> &SessionView {
        &self.session
    }

    /// Return the user and the session.
    pub fn into_parts(self) -> (UserView, SessionView) {
        (self.user, self.session)
    }
}

/// Permission checks bound to the configuration of the registered `AdminPlugin`.
///
/// Every check requires at least one resource and at least one action per resource. All
/// requested actions must be granted by one of the evaluated roles.
pub struct AdminPermissionApi<'a, S: AuthSchema> {
    config: &'a AdminConfig,
    context: &'a AuthContext<S>,
}

impl<'a, S: AuthSchema> AdminPermissionApi<'a, S> {
    /// Bind to the configuration that `AdminPlugin` published during initialization.
    pub fn from_context(context: &'a AuthContext<S>) -> Result<Self, AdminPermissionError> {
        let config = context
            .extensions
            .get::<AdminConfig>()
            .ok_or(AdminPermissionError::PluginNotRegistered)?;
        Ok(Self { config, context })
    }

    /// Evaluate a role string without identifying a user.
    ///
    /// This is not authentication. Use it only for a role that trusted server code already
    /// holds. Never pass a role that a client supplied. `role` may hold several roles separated
    /// by commas. Unknown roles grant nothing. `admin_user_ids` never applies because no user
    /// is identified.
    pub fn role_has_permission(
        &self,
        role: &str,
        permissions: &HashMap<String, Vec<String>>,
    ) -> Result<bool, AdminPermissionError> {
        require_permissions(permissions)?;
        if role.is_empty() {
            return Err(AdminPermissionError::MissingSubject);
        }
        // An undefined user ID is not truthy, so `admin_user_ids` never matches it.
        has_permission(
            &FieldValue::Undefined,
            &role.into(),
            self.config,
            permissions,
        )
        .map_err(AdminPermissionError::Internal)
    }

    /// Evaluate the current stored roles of a user from trusted server code.
    ///
    /// This reads the user on each call and does not check any session. The caller must
    /// authenticate the operator separately. A user without a role uses the configured default
    /// role. A user listed in `admin_user_ids` passes every check.
    ///
    /// A dynamic base URL needs a configured fallback for this requestless operation.
    pub async fn user_has_permission(
        &self,
        user_id: &str,
        permissions: &HashMap<String, Vec<String>>,
    ) -> Result<bool, AdminPermissionError> {
        require_permissions(permissions)?;
        if user_id.is_empty() {
            return Err(AdminPermissionError::MissingSubject);
        }
        let user = self
            .context
            .with_native_context(NativeRequest::default(), |context| async move {
                context.database.get_user_by_id(user_id).await
            })
            .await
            .map_err(AdminPermissionError::Internal)?
            .ok_or(AdminPermissionError::UserNotFound)?;
        has_permission(
            &user.id.field_value(),
            &user.role.field_value(),
            self.config,
            permissions,
        )
        .map_err(AdminPermissionError::Internal)
    }

    /// Authenticate the caller from request headers, then require the permissions.
    ///
    /// The session and the user come from the framework session store on every call. Request
    /// bodies and client claims never select the user or the role. With a database or secondary
    /// storage, this read skips the cookie cache. A revoked session or a removed role therefore
    /// takes effect on the next call. The check does not return refreshed session cookies.
    pub async fn authorize_request(
        &self,
        headers: &HashMap<String, String>,
        permissions: &HashMap<String, Vec<String>>,
    ) -> Result<AuthorizedSession, AdminPermissionError> {
        require_permissions(permissions)?;
        let (user, session) = self
            .context
            .with_native_context(
                NativeRequest {
                    request: None,
                    headers: Some(headers),
                },
                |context| async move {
                    let request = AuthRequest::new(HttpMethod::Post, "/admin/has-permission")
                        .with_optional_headers(Some(headers.clone()));
                    let mut hook_context =
                        better_auth_core::RequestHookContext::from_request(&request)?;
                    hook_context.body = better_auth_core::FieldValue::from_json(
                        serde_json::json!({ "permissions": permissions }),
                    )?;
                    better_auth_core::with_request_hook_context_value(hook_context, async {
                        context.require_authoritative_session(&request).await
                    })
                    .await
                },
            )
            .await
            .map_err(session_error)?;
        if has_permission(
            &user.id.field_value(),
            &user.role.field_value(),
            self.config,
            permissions,
        )
        .map_err(AdminPermissionError::Internal)?
        {
            Ok(AuthorizedSession { user, session })
        } else {
            Err(AdminPermissionError::Forbidden)
        }
    }
}

fn require_permissions(
    permissions: &HashMap<String, Vec<String>>,
) -> Result<(), AdminPermissionError> {
    if permissions.is_empty() || permissions.values().any(Vec::is_empty) {
        Err(AdminPermissionError::EmptyPermissions)
    } else {
        Ok(())
    }
}

fn session_error(error: AuthError) -> AdminPermissionError {
    match error {
        AuthError::SessionNotFound | AuthError::UserNotFound => {
            AdminPermissionError::Unauthenticated
        }
        error if is_unauthorized(&error) => AdminPermissionError::Unauthenticated,
        error => AdminPermissionError::Internal(error),
    }
}

fn is_unauthorized(error: &AuthError) -> bool {
    error
        .status_code()
        .is_ok_and(|status| status.typed().is_ok_and(|status| *status == 401))
}
