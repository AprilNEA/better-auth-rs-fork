//! Callable field values retain callback identity and borrowed invocation context.

use crate::{AuthError, AuthResult, FieldMap, FieldObject, FieldValue};
use std::{any::Any, fmt, future::Future, pin::Pin, sync::Arc};

/// A field function. Clones retain the callback, properties, and original identity.
#[derive(Clone)]
pub struct FieldFunction(Arc<Function>);

type ContextualCallback =
    dyn Fn(&FieldValue, &[FieldValue]) -> AuthResult<FieldValue> + Send + Sync;
type CallbackFuture = Pin<Box<dyn Future<Output = AuthResult<FieldValue>> + Send>>;
type AsyncCallback = dyn Fn(FieldValue, Vec<FieldValue>) -> CallbackFuture + Send + Sync;

enum Callback {
    Sync(Box<ContextualCallback>),
    Async(Box<AsyncCallback>),
    Bound(Box<dyn Any + Send + Sync>),
}

struct Function {
    callback: Callback,
    properties: FieldObject,
}

impl FieldFunction {
    /// Create a callback that receives the borrowed receiver and ordered arguments.
    pub fn contextual(
        callback: impl Fn(&FieldValue, &[FieldValue]) -> AuthResult<FieldValue> + Send + Sync + 'static,
    ) -> Self {
        Self::contextual_with_properties(callback, FieldMap::new().into())
    }

    /// Create a distinct function whose property source owns accessors and descriptors.
    pub fn contextual_with_properties(
        callback: impl Fn(&FieldValue, &[FieldValue]) -> AuthResult<FieldValue> + Send + Sync + 'static,
        properties: FieldObject,
    ) -> Self {
        Self(Arc::new(Function {
            callback: Callback::Sync(Box::new(callback)),
            properties,
        }))
    }

    /// Create an awaited callback that owns invocation handles without copying their objects.
    pub fn asynchronous_contextual<F, Fut>(callback: F) -> Self
    where
        F: Fn(FieldValue, Vec<FieldValue>) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = AuthResult<FieldValue>> + Send + 'static,
    {
        Self::asynchronous_contextual_with_properties(callback, FieldMap::new().into())
    }

    /// Create an awaited callback with its own accessors and property descriptors.
    pub fn asynchronous_contextual_with_properties<F, Fut>(
        callback: F,
        properties: FieldObject,
    ) -> Self
    where
        F: Fn(FieldValue, Vec<FieldValue>) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = AuthResult<FieldValue>> + Send + 'static,
    {
        Self(Arc::new(Function {
            callback: Callback::Async(Box::new(move |receiver, arguments| {
                Box::pin(callback(receiver, arguments))
            })),
            properties,
        }))
    }

    /// Bind a host callback whose invocation borrows a context, such as a database transaction.
    /// The host retrieves the callback with `binding` and invokes it in the active context.
    pub fn bound<T: Send + Sync + 'static>(binding: T) -> Self {
        Self::bound_with_properties(binding, FieldMap::new().into())
    }

    /// Bind a host callback with its own accessors and property descriptors.
    pub fn bound_with_properties<T: Send + Sync + 'static>(
        binding: T,
        properties: FieldObject,
    ) -> Self {
        Self(Arc::new(Function {
            callback: Callback::Bound(Box::new(binding)),
            properties,
        }))
    }

    /// Borrow this function's host callback without consulting a separate identity registry.
    pub fn binding<T: 'static>(&self) -> Option<&T> {
        match &self.0.callback {
            Callback::Bound(binding) => binding.downcast_ref(),
            Callback::Sync(_) | Callback::Async(_) => None,
        }
    }

    /// Borrow the function's own named properties without invoking the function.
    pub fn properties(&self) -> &FieldObject {
        &self.0.properties
    }

    /// Invoke the callback with an undefined receiver and no arguments.
    pub fn call(&self) -> AuthResult<FieldValue> {
        self.call_with(&FieldValue::Undefined, &[])
    }

    /// Invoke a synchronous callback without changing its result, error, or argument handles.
    /// Awaited callbacks require `call_awaited_with`; host callbacks require their binding context.
    pub fn call_with(
        &self,
        receiver: &FieldValue,
        arguments: &[FieldValue],
    ) -> AuthResult<FieldValue> {
        match &self.0.callback {
            Callback::Sync(callback) => callback(receiver, arguments),
            // shortcut: synchronous Promise results are not represented; add a shared Promise value before exposing them.
            Callback::Async(_) => Err(AuthError::internal(
                "Field function requires an awaited call",
            )),
            Callback::Bound(_) => Err(AuthError::internal(
                "Field function requires its host context",
            )),
        }
    }

    /// Invoke and await a callback while retaining native receiver, argument, result, and error identity.
    /// A host callback must be invoked through `binding` with its active borrowed context.
    pub async fn call_awaited_with(
        &self,
        receiver: &FieldValue,
        arguments: &[FieldValue],
    ) -> AuthResult<FieldValue> {
        match &self.0.callback {
            Callback::Sync(callback) => callback(receiver, arguments),
            Callback::Async(callback) => callback(receiver.clone(), arguments.to_vec()).await,
            Callback::Bound(_) => Err(AuthError::internal(
                "Field function requires its host context",
            )),
        }
    }

    pub(crate) fn identity(&self) -> usize {
        Arc::as_ptr(&self.0) as usize
    }
}

impl From<FieldFunction> for FieldValue {
    fn from(function: FieldFunction) -> Self {
        Self::Function(function)
    }
}

impl PartialEq for FieldFunction {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.0, &other.0)
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
