//! HTTP routing error policy. Endpoint responses and native calls retain their own boundaries.

use std::future::{Future, poll_fn};
use std::pin::Pin;
use std::sync::Arc;
use std::task::Poll;

use crate::{AuthContext, AuthError, AuthResponse, AuthResult, AuthSchema};

/// Detached asynchronous work returned by an HTTP error callback.
pub type ApiErrorTask = Pin<Box<dyn Future<Output = AuthResult<()>> + Send + 'static>>;

/// Observe a router failure using the resolved authentication context.
///
/// Return `Err` to throw synchronously. Return a future for asynchronous work that must not
/// delay the response. The future starts before the response and continues in the request scope.
/// A detached failure receives a runtime diagnostic and cannot replace an already returned response.
pub trait ApiErrorHandler<S: AuthSchema>: Send + Sync {
    fn on_error(
        &self,
        error: &AuthError,
        context: &AuthContext<S>,
    ) -> AuthResult<Option<ApiErrorTask>>;
}

/// Preserve the owner of failures that cross the HTTP router boundary.
#[doc(hidden)]
pub enum HttpFailure {
    Source(AuthError),
    Conversion(AuthError),
}

impl HttpFailure {
    pub fn into_error(self) -> AuthError {
        match self {
            Self::Source(error) | Self::Conversion(error) => error,
        }
    }

    /// Convert a source failure once; a failed conversion already belongs to the host.
    pub fn into_response(self) -> AuthResult<AuthResponse> {
        match self {
            Self::Source(error) => error.to_http_response(),
            Self::Conversion(error) => Err(error),
        }
    }
}

impl From<AuthError> for HttpFailure {
    fn from(error: AuthError) -> Self {
        Self::Source(error)
    }
}

/// Apply the policy only at the HTTP router's endpoint invocation catch boundary.
pub async fn handle_http_error<S: AuthSchema>(
    error: AuthError,
    context: &AuthContext<S>,
) -> AuthResult<AuthResponse> {
    handle_http_error_for_transport(error, context)
        .await
        .map_err(HttpFailure::into_error)
}

/// Retain conversion ownership for transports that cannot propagate the original error.
#[doc(hidden)]
pub async fn handle_http_error_for_transport<S: AuthSchema>(
    error: AuthError,
    context: &AuthContext<S>,
) -> Result<AuthResponse, HttpFailure> {
    if error.is_found_redirect().map_err(HttpFailure::Conversion)? {
        return error
            .to_auth_response()
            .and_then(AuthResponse::into_http_response)
            .map_err(HttpFailure::Conversion);
    }
    if context.config.api_error.throw_errors() {
        return rethrow(error);
    }
    if let Some(callback) = context.extensions.get::<Arc<dyn ApiErrorHandler<S>>>() {
        let task = match callback.on_error(&error, context) {
            Ok(task) => task,
            Err(replacement) => return rethrow(replacement),
        };
        if let Some(mut task) = task {
            // JavaScript executes an async callback until its first suspension before returning its Promise.
            match poll_fn(|cx| Poll::Ready(task.as_mut().poll(cx))).await {
                Poll::Ready(result) => report_detached_error(result),
                Poll::Pending => {
                    drop(crate::request_runtime::spawn_with_request_context(
                        async move {
                            report_detached_error(task.await);
                        },
                    ));
                }
            }
        }
        return error.to_http_response().map_err(HttpFailure::Conversion);
    }
    if let Err(replacement) = error.log_http_error(context.logger(), &context.config.logger) {
        return rethrow(replacement);
    }
    error.to_http_response().map_err(HttpFailure::Conversion)
}

fn rethrow(error: AuthError) -> Result<AuthResponse, HttpFailure> {
    // The outer HTTP router still serializes thrown API errors, including callback replacements.
    if error.is_api_error().map_err(HttpFailure::Conversion)? {
        error
            .to_auth_response()
            .and_then(AuthResponse::into_http_response)
            .map_err(HttpFailure::Conversion)
    } else {
        Err(HttpFailure::Source(error))
    }
}

fn report_detached_error(result: AuthResult<()>) {
    if let Err(error) = result {
        crate::observability::report_terminal_error("onAPIError callback", error);
    }
}
