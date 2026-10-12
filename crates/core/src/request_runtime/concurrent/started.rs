use crate::{AuthError, AuthResult};
use futures_util::future::BoxFuture;
use std::{
    future::Future,
    pin::Pin,
    task::{Context, Poll},
};

/// An operation whose synchronous prefix has run before its result collector is installed.
/// Dropping the operation retains its work and reports an otherwise unowned terminal error.
#[doc(hidden)]
pub struct StartedOperation<T: Send + 'static> {
    future: Option<BoxFuture<'static, AuthResult<T>>>,
    boundary: &'static str,
}

impl<T: Send + 'static> StartedOperation<T> {
    /// Start the operation in the caller's scope without observing its returned rejection.
    pub async fn new(
        boundary: &'static str,
        mut future: BoxFuture<'static, AuthResult<T>>,
    ) -> Self {
        let future = match super::first_poll(future.as_mut()).await {
            Poll::Ready(result) => Box::pin(std::future::ready(result)) as BoxFuture<'_, _>,
            Poll::Pending => future,
        };
        Self {
            future: Some(future),
            boundary,
        }
    }
}

impl<T: Send + 'static> Future for StartedOperation<T> {
    type Output = AuthResult<T>;

    fn poll(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Self::Output> {
        let Some(future) = self.future.as_mut() else {
            return Poll::Ready(Err(AuthError::internal(
                "Started operation was polled after completion",
            )));
        };
        let result = future.as_mut().poll(context);
        if result.is_ready() {
            self.future = None;
        }
        result
    }
}

impl<T: Send + 'static> Drop for StartedOperation<T> {
    fn drop(&mut self) {
        if let Some(future) = self.future.take() {
            let boundary = self.boundary;
            drop(crate::request_runtime::spawn_with_request_context(
                async move {
                    if let Err(error) = future.await {
                        crate::observability::report_terminal_error(boundary, error);
                    }
                },
            ));
        }
    }
}
