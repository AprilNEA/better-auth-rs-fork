//! Concurrent adapter operations retain started peers after the caller receives an error.

use crate::{AuthError, AuthResult};
use std::future::{Future, poll_fn};
use std::pin::pin;
use tokio::sync::mpsc::{UnboundedSender, unbounded_channel};

#[cfg(test)]
mod tests;

enum Progress {
    Started,
    Failed(AuthError),
}

async fn report<T>(
    future: impl Future<Output = AuthResult<T>>,
    progress: UnboundedSender<Progress>,
) -> Option<T> {
    let mut future = pin!(future);
    let mut started = false;
    let result = poll_fn(|context| {
        let result = future.as_mut().poll(context);
        if !started {
            started = true;
            let _ = progress.send(Progress::Started);
        }
        result
    })
    .await;
    match result {
        Ok(value) => Some(value),
        Err(error) => {
            let _ = progress.send(Progress::Failed(error));
            None
        }
    }
}

async fn supervise<T: Send + 'static, F>(
    name: &'static str,
    peers: usize,
    work: impl FnOnce(UnboundedSender<Progress>) -> F,
) -> AuthResult<T>
where
    F: Future<Output = Option<T>> + Send + 'static,
{
    let (progress, mut receiver) = unbounded_channel();
    let task = super::scope::spawn(work(progress));
    let mut started = 0;
    let mut first_error = None;
    while let Some(progress) = receiver.recv().await {
        match progress {
            Progress::Started => started += 1,
            Progress::Failed(error) => {
                let _ = first_error.get_or_insert(error);
            }
        }
        // A different executor thread must not return before every peer finishes its synchronous prefix.
        if started == peers
            && let Some(error) = first_error.take()
        {
            // Dropping the handle detaches the supervisor; peers retain their request context.
            return Err(error);
        }
    }
    match task.await {
        Ok(Some(value)) => Ok(value),
        Ok(None) => Err(AuthError::internal(format!(
            "{name} completed without a result or an error",
        ))),
        Err(error) if error.is_panic() => std::panic::resume_unwind(error.into_panic()),
        Err(error) => Err(AuthError::internal(format!("{name}: {error}"))),
    }
}

/// Start peers in declaration order and return ordered results or the first error.
/// A returned error does not cancel the supervisor or any started peer.
pub async fn all<T: Send + 'static, F>(
    name: &'static str,
    futures: impl IntoIterator<Item = F>,
) -> AuthResult<Vec<T>>
where
    F: Future<Output = AuthResult<T>> + Send + 'static,
{
    let futures = futures.into_iter().collect::<Vec<_>>();
    supervise(name, futures.len(), move |errors| async move {
        futures_util::future::join_all(
            futures
                .into_iter()
                .map(|future| report(future, errors.clone())),
        )
        .await
        .into_iter()
        .collect()
    })
    .await
}

/// Start the left operation before the right operation and retain both after an error.
pub async fn pair<A: Send + 'static, B: Send + 'static>(
    name: &'static str,
    left: impl Future<Output = AuthResult<A>> + Send + 'static,
    right: impl Future<Output = AuthResult<B>> + Send + 'static,
) -> AuthResult<(A, B)> {
    supervise(name, 2, move |errors| async move {
        let (left, right) =
            futures_util::future::join(report(left, errors.clone()), report(right, errors)).await;
        left.zip(right)
    })
    .await
}

/// Preserve the factory's await after a backend operation, including an already-ready error.
pub async fn adapter_result<T>(result: AuthResult<T>) -> AuthResult<T> {
    crate::user_fields::await_adapter_boundary().await;
    result
}
