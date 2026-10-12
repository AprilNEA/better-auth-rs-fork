use crate::{AuthRequest, AuthResult};
use std::{future::Future, pin::Pin, sync::Arc};

use super::ValidatedInput;

type ValidationFuture = Pin<Box<dyn Future<Output = AuthResult<ValidatedInput>> + Send>>;
type SyncCallback = dyn Fn(&AuthRequest) -> AuthResult<ValidatedInput> + Send + Sync;

/// One native input validator, evaluated once at the route's configured validation phase.
#[derive(Clone)]
pub struct InputValidator(Callback);

/// A body validator runs before query validation and endpoint middleware.
pub type BodyValidator = InputValidator;

/// A query validator runs after body validation and before endpoint middleware.
pub type QueryValidator = InputValidator;

#[derive(Clone)]
enum Callback {
    Sync(Arc<SyncCallback>),
    Async(Arc<dyn Fn(AuthRequest) -> ValidationFuture + Send + Sync>),
}

impl InputValidator {
    /// Retain a synchronous validator without projecting native input.
    pub fn new(
        callback: impl Fn(&AuthRequest) -> AuthResult<ValidatedInput> + Send + Sync + 'static,
    ) -> Self {
        Self(Callback::Sync(Arc::new(callback)))
    }

    /// Give an asynchronous validator its own request snapshot.
    pub fn new_async<F, Fut>(callback: F) -> Self
    where
        F: Fn(AuthRequest) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = AuthResult<ValidatedInput>> + Send + 'static,
    {
        Self(Callback::Async(Arc::new(move |request| {
            Box::pin(callback(request))
        })))
    }

    /// Evaluate the configured validator exactly once and preserve its original error.
    pub async fn validate(&self, request: &AuthRequest) -> AuthResult<ValidatedInput> {
        match &self.0 {
            Callback::Sync(callback) => callback(request),
            Callback::Async(callback) => callback(request.clone()).await,
        }
    }
}
