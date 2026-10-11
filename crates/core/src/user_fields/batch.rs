use super::UserFieldConfig;
use crate::AuthResult;
use futures_util::{
    Stream, StreamExt,
    future::BoxFuture,
    stream::{self, BoxStream, FuturesUnordered},
};
use indexmap::IndexMap;
use std::{
    future::{Future, poll_fn},
    task::Poll,
};

type ReadyRow<'a, T> = (usize, &'a mut T, usize);

pub(crate) async fn await_boundary() {
    let mut queued = false;
    poll_fn(|context| {
        if queued {
            return Poll::Ready(());
        }
        queued = true;
        // Wake the callback queue directly; Tokio's deferred yields reverse ready peers.
        context.waker().wake_by_ref();
        Poll::Pending
    })
    .await;
}

async fn start_callback<T>(callback: &mut BoxFuture<'_, T>) -> Poll<T> {
    // JavaScript runs each callback's synchronous prefix before starting the next row.
    poll_fn(|cx| Poll::Ready(callback.as_mut().poll(cx))).await
}

fn source_projection_results<'a, T: Send, V: Send + 'a, R: Send + 'a>(
    rows: &'a mut [T],
    fields: &'a IndexMap<String, UserFieldConfig>,
    read: &'a (impl Fn(&mut T, &str, &UserFieldConfig) -> AuthResult<V> + Sync),
    apply: &'a (
            impl for<'b> Fn(&'b mut T, &'b str, &'b UserFieldConfig, V) -> BoxFuture<'b, AuthResult<()>>
            + Sync
        ),
    complete: &'a (impl Fn(usize, &mut T) -> AuthResult<R> + Sync),
) -> BoxStream<'a, AuthResult<(usize, R)>> {
    let capacity = rows.len().max(1);
    let ready: Vec<_> = rows
        .iter_mut()
        .enumerate()
        .map(|(index, row)| (index, row, 0))
        .collect();
    let pending: FuturesUnordered<BoxFuture<'a, AuthResult<ReadyRow<'a, T>>>> =
        FuturesUnordered::new();
    stream::unfold(
        (ready, pending),
        move |(mut ready, mut pending)| async move {
            let mut completed = Vec::new();
            loop {
                for (index, row, mut position) in ready {
                    loop {
                        let Some((name, field)) = fields.get_index(position) else {
                            completed.push(complete(index, row).map(|value| (index, value)));
                            break;
                        };
                        let value = match read(row, name, field) {
                            Ok(value) => value,
                            Err(error) => {
                                completed.push(Err(error));
                                break;
                            }
                        };
                        position += 1;
                        if field.output_transform().is_some() {
                            // Capture only this field. Later fields must observe writes made while awaiting.
                            let mut callback: BoxFuture<'a, AuthResult<ReadyRow<'a, T>>> =
                                Box::pin(async move {
                                    apply(row, name, field, value).await?;
                                    Ok((index, row, position))
                                });
                            match start_callback(&mut callback).await {
                                Poll::Ready(Ok(row)) => {
                                    pending.push(Box::pin(std::future::ready(Ok(row))))
                                }
                                Poll::Ready(Err(error)) => completed.push(Err(error)),
                                Poll::Pending => pending.push(callback),
                            }
                            break;
                        }
                        if let Err(error) = apply(row, name, field, value).await {
                            completed.push(Err(error));
                            break;
                        }
                    }
                }
                // Expose completed parents before polling suspended peers for another field.
                if !completed.is_empty() {
                    return Some((completed, (Vec::new(), pending)));
                }
                let batch = pending.by_ref().ready_chunks(capacity).next().await?;
                ready = Vec::new();
                for result in batch {
                    match result {
                        Ok(row) => ready.push(row),
                        Err(error) => completed.push(Err(error)),
                    }
                }
            }
        },
    )
    .flat_map(stream::iter)
    .boxed()
}

fn source_apply<T, F>(apply: F) -> F
where
    F: for<'a> Fn(&'a mut T, &'a str, &'a UserFieldConfig, ()) -> BoxFuture<'a, AuthResult<()>>
        + Sync,
{
    apply
}

/// Continue completed live rows without delaying their child reads behind suspended peers.
pub(crate) async fn project_source_fields_batches_then<T: Send, I: Send, V: Send, R: Send, F>(
    rows: &mut [T],
    fields: &IndexMap<String, UserFieldConfig>,
    read: impl Fn(&mut T, &str, &UserFieldConfig) -> AuthResult<I> + Sync,
    apply: impl for<'a> Fn(&'a mut T, &'a str, &'a UserFieldConfig, I) -> BoxFuture<'a, AuthResult<()>>
    + Sync,
    extract: impl Fn(usize, &mut T) -> AuthResult<V> + Sync,
    complete: impl Fn(Vec<(usize, V)>) -> F + Sync,
) -> AuthResult<Vec<R>>
where
    F: Future<Output = AuthResult<Vec<(usize, R)>>> + Send,
{
    let capacity = rows.len().max(1);
    let pending = source_projection_results(rows, fields, &read, &apply, &extract);
    continue_projection_batches(pending, capacity, None, complete).await
}

fn finish_projection<R>(
    first_error: Option<crate::AuthError>,
    completed: Vec<R>,
) -> AuthResult<Vec<R>> {
    // Drain started peers before returning the first original callback error.
    match first_error {
        Some(error) => Err(error),
        None => Ok(completed),
    }
}

async fn collect_projection<R: Send, B: IntoIterator<Item = (usize, R)> + Send>(
    pending: impl Stream<Item = AuthResult<B>> + Send,
    mut failed: impl FnMut(crate::AuthError) + Send,
) -> Vec<R> {
    futures_util::pin_mut!(pending);
    let mut completed = Vec::new();
    while let Some(result) = pending.next().await {
        match result {
            Ok(rows) => completed.extend(rows),
            Err(error) => failed(error),
        }
    }
    completed.sort_unstable_by_key(|(index, _)| *index);
    completed.into_iter().map(|(_, value)| value).collect()
}

pub(crate) async fn project_fields<T: Send>(
    rows: &mut [T],
    fields: &IndexMap<String, UserFieldConfig>,
    project: impl for<'a> Fn(&'a mut T, &'a str, &'a UserFieldConfig) -> BoxFuture<'a, AuthResult<()>>
    + Sync,
) -> AuthResult<()> {
    project_fields_then(rows, fields, project, |_, _| std::future::ready(Ok(())))
        .await
        .map(|_| ())
}

pub(crate) async fn project_fields_then<T: Send, R: Send, F>(
    rows: &mut [T],
    fields: &IndexMap<String, UserFieldConfig>,
    project: impl for<'a> Fn(&'a mut T, &'a str, &'a UserFieldConfig) -> BoxFuture<'a, AuthResult<()>>
    + Sync,
    complete: impl Fn(usize, &mut T) -> F + Sync,
) -> AuthResult<Vec<R>>
where
    F: Future<Output = AuthResult<R>> + Send,
{
    let mut first_error = None;
    let completed = project_fields_then_collect(rows, fields, &project, &complete, |error| {
        let _ = first_error.get_or_insert(error);
    })
    .await;
    finish_projection(first_error, completed)
}

async fn project_fields_then_collect<T: Send, R: Send, F>(
    rows: &mut [T],
    fields: &IndexMap<String, UserFieldConfig>,
    project: &(
         impl for<'a> Fn(&'a mut T, &'a str, &'a UserFieldConfig) -> BoxFuture<'a, AuthResult<()>> + Sync
     ),
    complete: &(impl Fn(usize, &mut T) -> F + Sync),
    failed: impl FnMut(crate::AuthError) + Send,
) -> Vec<R>
where
    F: Future<Output = AuthResult<R>> + Send,
{
    let capacity = rows.len().max(1);
    let read = |_: &mut T, _: &str, _: &UserFieldConfig| Ok(());
    let apply = source_apply(|row, name, field, ()| project(row, name, field));
    let extract = |index, row: &mut T| Ok(complete(index, row));
    let pending = source_projection_results(rows, fields, &read, &apply, &extract)
        .map(|result| async move {
            let (index, complete) = result?;
            Ok([(index, complete.await?)])
        })
        .buffer_unordered(capacity);
    collect_projection(pending, failed).await
}

pub(crate) async fn project_owned_fields_then<T: Send + 'static, R: Send + 'static, F>(
    mut rows: Vec<T>,
    fields: IndexMap<String, UserFieldConfig>,
    project: impl for<'a> Fn(&'a mut T, &'a str, &'a UserFieldConfig) -> BoxFuture<'a, AuthResult<()>>
    + Send
    + Sync
    + 'static,
    complete: impl Fn(usize, &mut T) -> F + Send + Sync + 'static,
) -> AuthResult<Vec<R>>
where
    F: Future<Output = AuthResult<R>> + Send + 'static,
{
    crate::request_runtime::concurrent::retain("Field projection", move |reporter| async move {
        let mut failed = false;
        let completed =
            project_fields_then_collect(&mut rows, &fields, &project, &complete, |error| {
                failed = true;
                reporter.failed(error);
            })
            .await;
        (!failed).then_some(completed)
    })
    .await
}

/// Continue currently ready rows together without waiting for suspended peer rows.
/// A failed row skips its continuation; other started rows retain their write and output stages.
pub(crate) async fn project_fields_batches_then<T: Send, V: Send, R: Send, F>(
    rows: &mut [T],
    fields: &IndexMap<String, UserFieldConfig>,
    project: impl for<'a> Fn(&'a mut T, &'a str, &'a UserFieldConfig) -> BoxFuture<'a, AuthResult<()>>
    + Sync,
    extract: impl Fn(usize, &mut T) -> AuthResult<V> + Sync,
    complete: impl Fn(Vec<(usize, V)>) -> F + Sync,
) -> AuthResult<Vec<R>>
where
    F: Future<Output = AuthResult<Vec<(usize, R)>>> + Send,
{
    let capacity = rows.len().max(1);
    let read = |_: &mut T, _: &str, _: &UserFieldConfig| Ok(());
    let apply = source_apply(|row, name, field, ()| project(row, name, field));
    let pending = source_projection_results(rows, fields, &read, &apply, &extract);
    continue_projection_batches(pending, capacity, None, complete).await
}

fn projection_batches<'a, V: Send + 'a, R: Send + 'a, F>(
    pending: impl Stream<Item = AuthResult<(usize, V)>> + Send + 'a,
    capacity: usize,
    complete: &'a (impl Fn(Vec<(usize, V)>) -> F + Sync),
) -> BoxStream<'a, AuthResult<Vec<(usize, R)>>>
where
    F: Future<Output = AuthResult<Vec<(usize, R)>>> + Send + 'a,
{
    Box::pin(pending)
        .ready_chunks(capacity)
        .map(move |batch| {
            let mut ready = Vec::new();
            let mut errors = Vec::new();
            for result in batch {
                match result {
                    Ok(row) => ready.push(row),
                    Err(error) => errors.push(Err(error)),
                }
            }
            // Poll parent projections while earlier batches await their child output.
            stream::iter(errors).chain(Box::pin(stream::once(async move {
                if ready.is_empty() {
                    Ok(Vec::new())
                } else {
                    complete(ready).await
                }
            })))
        })
        .flatten_unordered(None)
        .boxed()
}

async fn continue_projection_batches<V: Send, R: Send, F>(
    pending: impl Stream<Item = AuthResult<(usize, V)>> + Send,
    capacity: usize,
    mut first_error: Option<crate::AuthError>,
    complete: impl Fn(Vec<(usize, V)>) -> F + Sync,
) -> AuthResult<Vec<R>>
where
    F: Future<Output = AuthResult<Vec<(usize, R)>>> + Send,
{
    let completed = collect_projection(projection_batches(pending, capacity, &complete), |error| {
        let _ = first_error.get_or_insert(error);
    })
    .await;
    finish_projection(first_error, completed)
}

pub(crate) async fn project_owned_source_fields_batches_then<
    T: Send + 'static,
    I: Send + 'static,
    V: Send + 'static,
    R: Send + 'static,
    F,
>(
    mut rows: Vec<T>,
    fields: IndexMap<String, UserFieldConfig>,
    read: impl Fn(&mut T, &str, &UserFieldConfig) -> AuthResult<I> + Send + Sync + 'static,
    apply: impl for<'a> Fn(&'a mut T, &'a str, &'a UserFieldConfig, I) -> BoxFuture<'a, AuthResult<()>>
    + Send
    + Sync
    + 'static,
    extract: impl Fn(usize, &mut T) -> AuthResult<V> + Send + Sync + 'static,
    complete: impl Fn(Vec<(usize, V)>) -> F + Send + Sync + 'static,
) -> AuthResult<Vec<R>>
where
    F: Future<Output = AuthResult<Vec<(usize, R)>>> + Send + 'static,
{
    crate::request_runtime::concurrent::retain("Field projection", move |reporter| async move {
        let capacity = rows.len().max(1);
        let pending = source_projection_results(&mut rows, &fields, &read, &apply, &extract);
        let mut failed = false;
        let completed =
            collect_projection(projection_batches(pending, capacity, &complete), |error| {
                failed = true;
                reporter.failed(error);
            })
            .await;
        (!failed).then_some(completed)
    })
    .await
}
