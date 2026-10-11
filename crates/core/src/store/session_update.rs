use std::sync::Arc;

use super::{AuthTransaction, TypedTransactionFuture};
use crate::{AuthSchema, FieldMap, FieldValue, wire::SessionView};

/// A secondary write that runs after update-before hooks and before the database write.
pub struct SessionUpdateWriter {
    /// Run the database update after the secondary write succeeds.
    pub write_database: bool,
    /// Receive the complete hook patch, before adapter field transformations.
    pub write: Box<
        dyn FnOnce(
                crate::FieldMap,
            ) -> TypedTransactionFuture<'static, Option<crate::wire::SessionView>>
            + Send,
    >,
}

/// Bind the same secondary update policy to each token in a transaction.
#[derive(Clone)]
pub struct SessionUpdateWriterFactory {
    pub write_database: bool,
    pub write: Arc<
        dyn Fn(FieldValue, FieldMap) -> TypedTransactionFuture<'static, Option<SessionView>>
            + Send
            + Sync,
    >,
}

impl SessionUpdateWriterFactory {
    pub fn bind(&self, token: FieldValue) -> SessionUpdateWriter {
        let write = self.write.clone();
        SessionUpdateWriter {
            write_database: self.write_database,
            write: Box::new(move |fields| write(token, fields)),
        }
    }
}

/// Await a projected Session effect before committing its active transaction.
pub type SessionTransactionEffect<S> = Box<
    dyn FnOnce(SessionView, Arc<dyn AuthTransaction<S>>) -> TypedTransactionFuture<'static, ()>
        + Send,
>;

/// Carry secondary writes and one caller-selected output effect through a transaction.
pub struct SessionWriteEffects<S: AuthSchema> {
    pub secondary: Option<SessionUpdateWriterFactory>,
    pub after_output: Option<SessionTransactionEffect<S>>,
}

impl<S: AuthSchema> Default for SessionWriteEffects<S> {
    fn default() -> Self {
        Self {
            secondary: None,
            after_output: None,
        }
    }
}

impl<S: AuthSchema> SessionWriteEffects<S> {
    pub fn write_database(&self) -> bool {
        self.secondary
            .as_ref()
            .is_none_or(|writer| writer.write_database)
    }
}
