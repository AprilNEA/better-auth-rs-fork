//! Notification work that can outlive an endpoint and its transaction.

#[cfg(test)]
mod tests;

use crate::{
    AuthResult, FieldValue,
    observability::{LogArgument, Logger},
};
use std::{
    fmt,
    future::Future,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

/// An application notification that may run after its endpoint completes.
pub struct BackgroundFuture(Pin<Box<dyn Future<Output = AuthResult<FieldValue>> + Send + 'static>>);

impl BackgroundFuture {
    /// Wrap notification work whose successful completion has no value.
    pub fn new(future: impl Future<Output = AuthResult<()>> + Send + 'static) -> Self {
        Self::native(async move { future.await.map(|()| FieldValue::Undefined) })
    }

    /// Preserve the task's native completion value and object identity.
    pub fn native(future: impl Future<Output = AuthResult<FieldValue>> + Send + 'static) -> Self {
        Self(Box::pin(future))
    }
}

impl Future for BackgroundFuture {
    type Output = AuthResult<FieldValue>;

    fn poll(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Self::Output> {
        self.0.as_mut().poll(context)
    }
}

/// An already-running notification. Dropping this handle does not cancel the task.
/// Awaiting the handle preserves its native completion value and error ownership.
pub struct BackgroundTask(tokio::task::JoinHandle<AuthResult<FieldValue>>);
impl Future for BackgroundTask {
    type Output = Result<AuthResult<FieldValue>, tokio::task::JoinError>;
    fn poll(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Self::Output> {
        Pin::new(&mut self.0).poll(context)
    }
}

/// Application integration for retaining background tasks until delivery completes.
#[derive(Clone)]
pub struct BackgroundTasks(Arc<dyn Fn(BackgroundTask) -> AuthResult<()> + Send + Sync>);
impl fmt::Debug for BackgroundTasks {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BackgroundTasks").finish_non_exhaustive()
    }
}
impl BackgroundTasks {
    /// Receive a running task, for example to register the task with a server lifetime manager.
    pub fn new(handler: impl Fn(BackgroundTask) -> AuthResult<()> + Send + Sync + 'static) -> Self {
        Self(Arc::new(handler))
    }
}

fn log_failure(logger: &Logger, message: &str, error: &crate::AuthError) -> AuthResult<()> {
    logger.error(message, &[LogArgument::Error(error)])
}

#[derive(Clone, Copy)]
enum TaskPolicy {
    Await,
    AwaitWithCatch(&'static str),
    DetachedWithCatch(&'static str),
    DetachedWithCatches(&'static [&'static str]),
}

impl TaskPolicy {
    fn detached(self) -> bool {
        matches!(
            self,
            Self::DetachedWithCatch(_) | Self::DetachedWithCatches(_)
        )
    }

    fn catch(self, logger: &Logger, result: AuthResult<FieldValue>) -> AuthResult<FieldValue> {
        match self {
            Self::Await => catch_errors(logger, result, &["Failed to run background task:"]),
            Self::AwaitWithCatch(message) => {
                catch_errors(logger, result, &[message, "Failed to run background task:"])
            }
            Self::DetachedWithCatch(message) => catch_errors(logger, result, &[message]),
            Self::DetachedWithCatches(messages) => catch_errors(logger, result, messages),
        }
    }
}

fn catch_errors(
    logger: &Logger,
    mut result: AuthResult<FieldValue>,
    messages: &[&str],
) -> AuthResult<FieldValue> {
    for message in messages {
        result = result
            .or_else(|error| log_failure(logger, message, &error).map(|()| FieldValue::Undefined));
    }
    result
}

async fn first_poll(task: &mut BackgroundFuture) -> Poll<AuthResult<FieldValue>> {
    std::future::poll_fn(|context| Poll::Ready(Pin::new(&mut *task).poll(context))).await
}

/// Start an unowned promise and report its terminal rejection without an application catch.
#[doc(hidden)]
pub async fn start_unowned(task: BackgroundFuture, boundary: &'static str) {
    start_unowned_with_error_messages(
        task,
        &crate::observability::logger::current(),
        &[],
        boundary,
    )
    .await;
}

/// Start an unowned promise with its source catch layers and retain terminal error ownership.
#[doc(hidden)]
pub async fn start_unowned_with_error_messages(
    mut task: BackgroundFuture,
    logger: &Logger,
    error_messages: &'static [&'static str],
    boundary: &'static str,
) {
    let first = first_poll(&mut task).await;
    let logger = logger.clone();
    let finish = move |result| {
        if let Err(error) = catch_errors(&logger, result, error_messages) {
            crate::observability::report_terminal_error(boundary, error);
        }
    };
    match first {
        Poll::Ready(result) => finish(result),
        Poll::Pending => {
            drop(crate::request_runtime::spawn_with_request_context(
                async move {
                    finish(task.await);
                },
            ));
        }
    }
}

/// Await a notification by default, or hand its running task to the configured handler.
/// Callback factories run before this function; their synchronous errors remain endpoint errors.
pub async fn run_or_await(
    task: Option<BackgroundFuture>,
    handler: Option<&BackgroundTasks>,
    logger: &Logger,
) -> AuthResult<()> {
    run(task, handler, logger, TaskPolicy::Await).await
}

/// Schedule delivery with its endpoint-specific failure message.
/// Handler failures retain the shared background-task error message.
#[doc(hidden)]
pub async fn run_or_await_with_error_message(
    task: Option<BackgroundFuture>,
    handler: Option<&BackgroundTasks>,
    logger: &Logger,
    error_message: &'static str,
) -> AuthResult<()> {
    run(
        task,
        handler,
        logger,
        TaskPolicy::AwaitWithCatch(error_message),
    )
    .await
}

/// Start a task with one custom catch and transfer its result to the configured handler.
/// Without a handler, upstream explicitly suppresses the caught task's final rejection.
#[doc(hidden)]
pub async fn run_in_background_with_error_message(
    task: BackgroundFuture,
    handler: Option<&BackgroundTasks>,
    logger: &Logger,
    error_message: &'static str,
) -> AuthResult<()> {
    run(
        Some(task),
        handler,
        logger,
        TaskPolicy::DetachedWithCatch(error_message),
    )
    .await
}

/// Transfer a promise with ordered source catch layers to the background handler.
#[doc(hidden)]
pub async fn run_in_background_with_error_messages(
    task: BackgroundFuture,
    handler: Option<&BackgroundTasks>,
    logger: &Logger,
    error_messages: &'static [&'static str],
) -> AuthResult<()> {
    run(
        Some(task),
        handler,
        logger,
        TaskPolicy::DetachedWithCatches(error_messages),
    )
    .await
}

async fn run(
    task: Option<BackgroundFuture>,
    handler: Option<&BackgroundTasks>,
    logger: &Logger,
    policy: TaskPolicy,
) -> AuthResult<()> {
    let Some(mut task) = task else {
        return Ok(());
    };
    if handler.is_none() && !policy.detached() {
        return policy.catch(logger, task.await).map(|_| ());
    }
    // JavaScript callbacks start before the handler receives their promise. Poll once
    // in the caller's context before transferring the pending Rust future.
    let first = first_poll(&mut task).await;
    let ready = match first {
        Poll::Ready(result) => Some(result),
        Poll::Pending => None,
    };
    let (start, task_start) = tokio::sync::oneshot::channel();
    let task_logger = logger.clone();
    let suppress = handler.is_none();
    let handle = crate::request_runtime::spawn_with_request_context(async move {
        // Losing the startup owner is a Rust task failure, not an application rejection.
        #[expect(
            clippy::expect_used,
            reason = "A lost startup owner is a Rust task failure and must remain a JoinError"
        )]
        let ready = task_start
            .await
            .expect("Background task startup owner must publish a completion decision");
        let result = match ready {
            Some(result) => result,
            None => policy.catch(&task_logger, task.await),
        };
        if suppress {
            // Upstream runInBackground installs p.catch(() => {}) without a handler.
            result.or(Ok(FieldValue::Undefined))
        } else {
            result
        }
    });
    let handler_result = match handler {
        Some(handler) => {
            let result = (handler.0)(BackgroundTask(handle));
            if policy.detached() {
                result
            } else {
                result
                    .or_else(|error| log_failure(logger, "Failed to run background task:", &error))
            }
        }
        None => {
            drop(handle);
            Ok(())
        }
    };
    // An already-rejected promise runs its catch after handler invocation and before
    // the awaiting endpoint continues. A worker must not race ahead of that handler.
    let completion = ready.map(|result| policy.catch(logger, result));
    // A dropped receiver belongs to Rust task shutdown; do not report the application result again.
    drop(start.send(completion));
    handler_result
}
