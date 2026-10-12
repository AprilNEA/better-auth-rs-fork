use crate::types::{AuthRequest, HttpMethod, RequestMeta};

/// Evaluate a before-hook matcher before entering the matched handler's tracing span.
/// Pass the dispatcher's hook request when present; direct native helpers can omit the request.
pub fn run_before_hook_matcher<T>(
    config: &crate::AuthConfig,
    request: Option<&AuthRequest>,
    source: &str,
    matcher: impl FnOnce() -> crate::AuthResult<T>,
) -> crate::AuthResult<T> {
    match matcher() {
        Ok(value) => Ok(value),
        Err(error) => {
            config.logger().error(
                &format!("An error occurred during {source} hook matcher execution:"),
                &[crate::observability::LogArgument::Error(&error)],
            );
            if let Some(request) = request {
                request.mark_hook_matcher_error();
            }
            Err(crate::AuthError::from_status(
                "INTERNAL_SERVER_ERROR",
                crate::FieldMap::from([(
                    "message".into(),
                    "An error occurred during hook matcher execution. Check the logs for more details."
                        .into(),
                )])
                .into(),
            ))
        }
    }
}

/// Request-derived data available to middleware, stores, and other hooks during request handling.
#[derive(Debug, Clone)]
pub struct RequestHookContext {
    /// Request snapshot for plugin callbacks; native calls still use `is_http` to identify HTTP.
    pub request: AuthRequest,
    /// True only while the HTTP router owns response serialization.
    /// Native calls can carry headers and still preserve their original errors.
    pub is_http: bool,
    pub method: HttpMethod,
    /// Matched endpoint template; native-only outer hooks have no endpoint path.
    pub path: Option<String>,
    /// Effective endpoint identifier for instrumentation.
    pub operation_id: Option<String>,
    /// Values captured from the matched endpoint path.
    pub params: std::collections::HashMap<String, String>,
    pub headers: std::collections::HashMap<String, String>,
    /// Effective query input, preserving native values and identities.
    pub query: crate::FieldValue,
    /// Parsed endpoint input. An absent request body remains absent.
    pub body: crate::FieldValue,
    pub meta: RequestMeta,
}

impl RequestHookContext {
    /// Build a request hook context from an incoming auth request.
    pub fn from_request(request: &AuthRequest) -> crate::AuthResult<Self> {
        Ok(Self {
            request: request.clone(),
            is_http: false,
            method: request.method().clone(),
            path: Some(request.path().to_string()),
            operation_id: None,
            params: Default::default(),
            headers: request.headers.clone(),
            query: request.input_query_field_value()?,
            body: request.hook_field_value(),
            meta: RequestMeta::from_request(request),
        })
    }
}

tokio::task_local! {
    static REQUEST_HOOK_CONTEXT: std::cell::RefCell<RequestHookContext>;
}

/// Run a future with request context available to downstream integrations.
pub async fn with_request_hook_context<T>(
    request: &AuthRequest,
    future: impl std::future::Future<Output = crate::AuthResult<T>>,
) -> crate::AuthResult<T> {
    with_request_hook_context_value(RequestHookContext::from_request(request)?, future).await
}

/// Run a future with an explicit request hook context.
pub fn with_request_hook_context_value<T>(
    request_context: RequestHookContext,
    future: impl std::future::Future<Output = T>,
) -> impl std::future::Future<Output = T> {
    // Validation nests another endpoint scope around the handler future.
    // Keep that future off each scope's stack frame.
    REQUEST_HOOK_CONTEXT.scope(std::cell::RefCell::new(request_context), Box::pin(future))
}

pub fn current_request_hook_context() -> Option<RequestHookContext> {
    REQUEST_HOOK_CONTEXT
        .try_with(|context| context.borrow().clone())
        .ok()
}

fn route_parameter(segment: &str) -> Option<&str> {
    segment.strip_prefix('{')?.strip_suffix('}')
}

pub(crate) fn upstream_route_path(path: &str) -> String {
    path.split('/')
        .map(|segment| match route_parameter(segment) {
            Some(name) => format!(":{name}"),
            None => segment.to_owned(),
        })
        .collect::<Vec<_>>()
        .join("/")
}

/// Record the matched endpoint without changing the request's actual path.
pub fn set_request_hook_route(path: &str, route: Option<&crate::AuthRoute>) {
    let mut params = std::collections::HashMap::new();
    let path = route.map_or_else(
        || path.to_owned(),
        |route| {
            for (segment, value) in route.path.split('/').zip(path.split('/')) {
                if let Some(name) = route_parameter(segment) {
                    let _ = params.insert(name.to_owned(), value.to_owned());
                }
            }
            upstream_route_path(&route.path)
        },
    );
    let _ = REQUEST_HOOK_CONTEXT.try_with(|context| {
        let mut context = context.borrow_mut();
        context.path = Some(path);
        context.operation_id = route.map(|route| {
            route
                .openapi
                .as_ref()
                .and_then(|metadata| metadata.operation_id.clone())
                .or_else(|| route.endpoint_key.clone())
                .unwrap_or_else(|| route.operation_id.clone())
        });
        context.params = params;
    });
}

/// Refresh the active snapshot after HTTP parsing or body replacement.
/// Preserve the matched route, trusted IP metadata, and HTTP error policy.
pub fn update_request_hook_context(request: &AuthRequest) -> crate::AuthResult<()> {
    let body = request.input_field_value()?;
    let query = request.input_query_field_value()?;
    let _ = REQUEST_HOOK_CONTEXT.try_with(|context| {
        let mut context = context.borrow_mut();
        context.method = request.method.clone();
        context.headers = request.headers.clone();
        context.query = query;
        context.body = body;
        context.request = request.clone();
    });
    Ok(())
}
