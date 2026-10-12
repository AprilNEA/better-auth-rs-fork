//! Callable field values retain callback identity and borrowed invocation context.

use crate::{AuthResult, FieldMap, FieldObject, FieldValue};
use std::{fmt, sync::Arc};

/// A synchronous field function. Clones retain the original callback identity.
#[derive(Clone)]
pub struct FieldFunction(Arc<Function>);

type ContextualCallback =
    dyn Fn(&FieldValue, &[FieldValue]) -> AuthResult<FieldValue> + Send + Sync;

struct Function {
    callback: Box<ContextualCallback>,
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
            callback: Box::new(callback),
            properties,
        }))
    }

    /// Borrow the function's own named properties without invoking the function.
    pub fn properties(&self) -> &FieldObject {
        &self.0.properties
    }

    /// Invoke the callback with an undefined receiver and no arguments.
    pub fn call(&self) -> AuthResult<FieldValue> {
        self.call_with(&FieldValue::Undefined, &[])
    }

    /// Invoke the callback without changing its result, error, or argument handles.
    pub fn call_with(
        &self,
        receiver: &FieldValue,
        arguments: &[FieldValue],
    ) -> AuthResult<FieldValue> {
        (self.0.callback)(receiver, arguments)
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
