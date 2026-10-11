use std::sync::Arc;

use crate::AuthResult;
use crate::store::SecondaryStorage;

pub(super) async fn delete_cached_tokens(
    storage: Arc<dyn SecondaryStorage>,
    tokens: Vec<String>,
) -> AuthResult<()> {
    crate::request_runtime::concurrent::all(
        "Session deletion task",
        tokens.into_iter().map(|token| {
            let storage = storage.clone();
            async move { storage.delete(&token).await }
        }),
    )
    .await
    .map(|_| ())
}
