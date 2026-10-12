use std::sync::Arc;

use crate::AuthResult;
use crate::request_runtime::concurrent::{self, StartedOperation};
use crate::store::SecondaryStorage;

pub(super) async fn delete_cached_tokens(
    storage: Arc<dyn SecondaryStorage>,
    tokens: Vec<String>,
) -> AuthResult<()> {
    let mut operations = Vec::with_capacity(tokens.len());
    for token in tokens {
        operations.push(
            StartedOperation::new(
                "Session unowned cache deletion",
                storage.clone().invoke_delete_native(token.into())?,
            )
            .await,
        );
    }
    concurrent::all("Session deletion task", operations)
        .await
        .map(|_| ())
}

#[cfg(test)]
mod tests;
