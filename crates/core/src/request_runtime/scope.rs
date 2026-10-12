use std::any::Any;
use std::future::Future;
use std::sync::Arc;

use crate::{AuthContext, AuthSchema};
use tracing::{Instrument, instrument::WithSubscriber};

/// Identity belongs to an auth instance, including all request-derived clones.
#[derive(Clone, Default)]
pub(crate) struct Identity(Arc<()>);

impl Identity {
    pub(crate) fn current<S: AuthSchema>(&self) -> Option<Arc<AuthContext<S>>> {
        current(self)
    }
}

#[derive(Clone)]
struct Binding {
    identity: Identity,
    logger: Option<crate::observability::LoggerConfig>,
    context: Arc<dyn Any + Send + Sync>,
}

tokio::task_local! {
    static CONTEXTS: Vec<Binding>;
}

pub(super) fn current<S: AuthSchema>(identity: &Identity) -> Option<Arc<AuthContext<S>>> {
    CONTEXTS
        .try_with(|contexts| {
            contexts
                .iter()
                .rev()
                .find(|binding| Arc::ptr_eq(&binding.identity.0, &identity.0))
                .and_then(|binding| binding.context.clone().downcast().ok())
        })
        .ok()
        .flatten()
}

pub(super) fn run<S: AuthSchema, T>(
    context: Arc<AuthContext<S>>,
    future: impl Future<Output = T>,
) -> impl Future<Output = T> {
    let logger = Some(context.config.logger.clone());
    run_with_logger(context, logger, future)
}

/// HTTP policy resolution must not replace the caller's endpoint or native helper logger.
pub(super) fn run_runtime<S: AuthSchema, T>(
    context: Arc<AuthContext<S>>,
    future: impl Future<Output = T>,
) -> impl Future<Output = T> {
    run_with_logger(context, None, future)
}

fn run_with_logger<S: AuthSchema, T>(
    context: Arc<AuthContext<S>>,
    logger: Option<crate::observability::LoggerConfig>,
    future: impl Future<Output = T>,
) -> impl Future<Output = T> {
    let mut contexts = CONTEXTS.try_with(Clone::clone).unwrap_or_default();
    contexts.push(Binding {
        identity: context.request_runtime.identity.clone(),
        logger,
        context,
    });
    // Keep large endpoint futures off each nested runtime scope's stack frame.
    CONTEXTS.scope(contexts, Box::pin(future))
}

/// Promise-all peers keep running after another resolver rejects.
pub(crate) fn spawn<T: Send + 'static>(
    future: impl Future<Output = T> + Send + 'static,
) -> tokio::task::JoinHandle<T> {
    let contexts = CONTEXTS.try_with(Clone::clone).unwrap_or_default();
    let request = crate::hooks::current_request_hook_context();
    tokio::spawn(
        crate::store::schema::SchemaValidation::inherit_transaction_scope(CONTEXTS.scope(
            contexts,
            async move {
                match request {
                    Some(request) => {
                        crate::hooks::with_request_hook_context_value(request, future).await
                    }
                    None => future.await,
                }
            },
        ))
        .in_current_span()
        .with_current_subscriber(),
    )
}

pub(super) fn current_logger() -> Option<crate::observability::LoggerConfig> {
    CONTEXTS
        .try_with(|contexts| {
            contexts
                .iter()
                .rev()
                .find_map(|binding| binding.logger.clone())
        })
        .ok()
        .flatten()
}
