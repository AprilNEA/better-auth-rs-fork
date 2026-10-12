use super::native;
use crate::{FieldMap, FieldValue};
use std::{error::Error as StdError, fmt, sync::OnceLock};
use thiserror::Error;

/// A database diagnostic with an optional source and a retained native error object.
#[derive(Error)]
#[error("{message}")]
pub struct DatabaseErrorCause {
    message: String,
    #[source]
    source: Option<Box<dyn StdError + Send + Sync>>,
    native_value: OnceLock<FieldValue>,
    captured_headers: Option<Box<FieldValue>>,
}

impl DatabaseErrorCause {
    /// Preserve the driver source and its available native properties.
    ///
    /// Properties retain insertion order. Error host properties `message`, `stack`, `line`, and `column` are nonenumerable.
    /// Omit properties when the driver has no native representation; callbacks then use the Rust diagnostic.
    pub fn from_source(
        message: impl Into<String>,
        source: impl StdError + Send + Sync + 'static,
        properties: Option<FieldMap>,
    ) -> Self {
        Self {
            message: message.into(),
            source: Some(Box::new(source)),
            native_value: properties
                .map(native::database_error)
                .map(OnceLock::from)
                .unwrap_or_default(),
            captured_headers: None,
        }
    }

    /// Borrow the original Rust diagnostic without reading native properties.
    pub fn as_str(&self) -> &str {
        &self.message
    }
}

impl From<String> for DatabaseErrorCause {
    fn from(message: String) -> Self {
        Self {
            message,
            source: None,
            native_value: OnceLock::new(),
            captured_headers: None,
        }
    }
}

impl From<&str> for DatabaseErrorCause {
    fn from(message: &str) -> Self {
        message.to_owned().into()
    }
}

impl fmt::Debug for DatabaseErrorCause {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DatabaseErrorCause")
            .field("message", &self.message)
            .field("source", &self.source)
            .finish_non_exhaustive()
    }
}

/// Database failure categories used by adapters and business retry policies.
#[derive(Error, Debug)]
pub enum DatabaseError {
    /// A database connection failed.
    #[error("Connection error: {0}")]
    Connection(#[source] DatabaseErrorCause),

    /// A database query failed.
    #[error("Query error: {0}")]
    Query(#[source] DatabaseErrorCause),

    /// A schema migration failed.
    #[error("Migration error: {0}")]
    Migration(#[source] DatabaseErrorCause),

    /// A database constraint rejected the operation.
    #[error("Constraint violation: {0}")]
    Constraint(#[source] DatabaseErrorCause),

    /// A uniqueness conflict that callers may resolve by generating another value.
    #[error("Unique constraint violation: {0}")]
    UniqueConstraint(#[source] DatabaseErrorCause),

    /// A database transaction failed.
    #[error("Transaction error: {0}")]
    Transaction(#[source] DatabaseErrorCause),
}

impl DatabaseError {
    /// Borrow the diagnostic and source while retaining the failure category.
    pub fn cause(&self) -> &DatabaseErrorCause {
        match self {
            Self::Connection(cause)
            | Self::Query(cause)
            | Self::Migration(cause)
            | Self::Constraint(cause)
            | Self::UniqueConstraint(cause)
            | Self::Transaction(cause) => cause,
        }
    }

    /// Whether regenerating a conflicting unique value may resolve this failure.
    pub fn is_unique_constraint(&self) -> bool {
        matches!(self, Self::UniqueConstraint(_))
    }

    pub(super) fn native_value(&self) -> &FieldValue {
        self.cause().native_value.get_or_init(|| {
            native::runtime_error("Error", format!("Database error: {self}").into())
        })
    }

    pub(super) fn capture_native_headers(&mut self, headers: FieldValue) {
        let cause = match self {
            Self::Connection(cause)
            | Self::Query(cause)
            | Self::Migration(cause)
            | Self::Constraint(cause)
            | Self::UniqueConstraint(cause)
            | Self::Transaction(cause) => cause,
        };
        cause.captured_headers = Some(Box::new(headers));
    }

    pub(super) fn captured_headers_value(&self) -> Option<FieldValue> {
        self.cause().captured_headers.as_deref().cloned()
    }
}

#[cfg(test)]
mod tests;
