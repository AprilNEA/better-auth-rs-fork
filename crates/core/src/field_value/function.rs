//! Callable field values retain callback identity and borrowed invocation context.

use crate::{AuthResult, FieldValue, user_fields::UserFieldFactory};
use std::{fmt, sync::Arc};

/// A synchronous field function. Clones retain the original callback identity.
#[derive(Clone)]
pub struct FieldFunction(Callback);

type ContextualCallback =
    dyn Fn(&FieldValue, &[FieldValue]) -> AuthResult<FieldValue> + Send + Sync;

#[derive(Clone)]
enum Callback {
    Factory(UserFieldFactory),
    Contextual(Arc<ContextualCallback>),
}

impl FieldFunction {
    /// Create a callback that receives the borrowed receiver and ordered arguments.
    pub fn contextual(
        callback: impl Fn(&FieldValue, &[FieldValue]) -> AuthResult<FieldValue> + Send + Sync + 'static,
    ) -> Self {
        Self(Callback::Contextual(Arc::new(callback)))
    }

    /// Invoke the callback with an undefined receiver and no arguments.
    pub fn call(&self) -> AuthResult<FieldValue> {
        self.call_with(&FieldValue::Undefined, &[])
    }

    /// Invoke the callback without changing its result, error, or argument handles.
    /// Legacy factories ignore the receiver and arguments.
    pub fn call_with(
        &self,
        receiver: &FieldValue,
        arguments: &[FieldValue],
    ) -> AuthResult<FieldValue> {
        match &self.0 {
            Callback::Factory(factory) => factory(),
            Callback::Contextual(callback) => callback(receiver, arguments),
        }
    }

    pub(crate) fn identity(&self) -> usize {
        match &self.0 {
            Callback::Factory(factory) => Arc::as_ptr(factory) as *const () as usize,
            Callback::Contextual(callback) => Arc::as_ptr(callback) as *const () as usize,
        }
    }
}

impl From<UserFieldFactory> for FieldFunction {
    fn from(factory: UserFieldFactory) -> Self {
        Self(Callback::Factory(factory))
    }
}

impl From<FieldFunction> for FieldValue {
    fn from(function: FieldFunction) -> Self {
        Self::Function(function)
    }
}

impl PartialEq for FieldFunction {
    fn eq(&self, other: &Self) -> bool {
        match (&self.0, &other.0) {
            (Callback::Factory(left), Callback::Factory(right)) => Arc::ptr_eq(left, right),
            (Callback::Contextual(left), Callback::Contextual(right)) => Arc::ptr_eq(left, right),
            _ => false,
        }
    }
}

impl Eq for FieldFunction {}

impl fmt::Debug for FieldFunction {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FieldFunction")
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
#[path = "function_tests.rs"]
mod tests;
