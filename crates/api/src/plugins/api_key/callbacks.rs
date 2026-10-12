use async_trait::async_trait;
use better_auth_core::{
    AuthConfig, AuthContext, AuthRequest, AuthResult, AuthSchema, FieldValue, RuntimeExtensions,
    plugin::MetadataMap,
    store::{ApiKeyStore, MemberStore, OrganizationStore},
};
use std::collections::HashMap;

/// Resource permissions assigned to an API key.
pub type ApiKeyPermissions = HashMap<String, Vec<String>>;

/// Endpoint data available to application API key callbacks.
#[derive(Clone, Copy)]
pub struct ApiKeyEndpoint<'a> {
    /// Original Request, absent for a requestless server API call.
    pub request: Option<&'a AuthRequest>,
    /// Endpoint headers, including headers supplied without an original Request.
    pub headers: Option<&'a HashMap<String, String>>,
    /// Endpoint path; absent in the server-only verification hook matcher.
    pub path: Option<&'a str>,
    /// Native endpoint input, including route defaults after validation.
    pub body: &'a FieldValue,
    /// Global authentication configuration.
    pub auth_config: &'a AuthConfig,
    /// Application runtime state registered with the authentication instance.
    pub extensions: &'a RuntimeExtensions,
    /// Metadata registered by enabled plugins.
    pub metadata: &'a MetadataMap,
    /// Database API key adapter, independent of the selected key storage mode.
    pub api_keys: &'a dyn ApiKeyStore,
    /// Organization adapter for organization-owned credentials.
    pub organizations: &'a dyn OrganizationStore,
    /// Organization memberships available to application permission policies.
    pub members: &'a dyn MemberStore,
}

impl<'a> ApiKeyEndpoint<'a> {
    pub(super) fn from_request<S: AuthSchema>(
        ctx: &'a AuthContext<S>,
        request: &'a AuthRequest,
        body: &'a FieldValue,
    ) -> Self {
        let original = request.original_request().or_else(|| {
            better_auth_core::hooks::current_request_hook_context()
                .is_some_and(|context| context.is_http)
                .then_some(request)
        });
        Self {
            headers: request.endpoint_headers(),
            ..Self::new(ctx, original, Some(request.path()), body)
        }
    }

    pub(super) fn new<S: AuthSchema>(
        ctx: &'a AuthContext<S>,
        request: Option<&'a AuthRequest>,
        path: Option<&'a str>,
        body: &'a FieldValue,
    ) -> Self {
        Self {
            request,
            headers: request.map(|request| &request.headers),
            path,
            body,
            auth_config: &ctx.config,
            extensions: &ctx.extensions,
            metadata: &ctx.metadata,
            api_keys: ctx.database.as_ref(),
            organizations: ctx.database.as_ref(),
            members: ctx.database.as_ref(),
        }
    }
}

/// Application credential generation, before hashing and starting-character storage.
#[async_trait]
pub trait ApiKeyGenerator: Send + Sync {
    async fn generate(&self, length: usize, prefix: Option<&str>) -> AuthResult<String>;
}

/// Synchronous key extraction used by the session hook matcher and handler.
pub trait ApiKeyGetter: Send + Sync {
    fn get(&self, ctx: ApiKeyEndpoint<'_>) -> AuthResult<Option<String>>;
}

/// Application validation before credential state and permission checks.
#[async_trait]
pub trait ApiKeyValidator: Send + Sync {
    async fn validate(&self, key: &str, ctx: ApiKeyEndpoint<'_>) -> AuthResult<bool>;
}

/// Dynamic creation permissions. Explicit permissions still cause this callback to run.
#[async_trait]
pub trait ApiKeyDefaultPermissions: Send + Sync {
    async fn permissions(
        &self,
        reference_id: &better_auth_core::FieldValue,
        ctx: ApiKeyEndpoint<'_>,
    ) -> AuthResult<ApiKeyPermissions>;
}
