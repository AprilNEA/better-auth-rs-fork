#![allow(
    clippy::expect_used,
    reason = "The storage contract requires an open event receiver and an unpoisoned fixture lock."
)]

use super::*;
use crate::{AuthError, FieldMap, FieldValue};
use async_trait::async_trait;
use std::sync::Mutex;
use tokio::sync::{Semaphore, mpsc};

struct Storage {
    synchronous_failure: bool,
    original: FieldValue,
    invoked: Mutex<Vec<String>>,
    deleted: Mutex<Vec<String>>,
    release: Semaphore,
    completed: mpsc::UnboundedSender<()>,
}

#[async_trait]
impl SecondaryStorage for Storage {
    fn invoke_delete_native(
        self: Arc<Self>,
        key: FieldValue,
    ) -> AuthResult<crate::store::SecondaryStorageFuture<()>> {
        let key: String = key.decode()?;
        self.invoked.lock().expect("fixture lock").push(key.clone());
        if key == "failure" && self.synchronous_failure {
            return Err(AuthError::from_thrown(self.original.clone()));
        }
        Ok(Box::pin(async move {
            if key == "failure" {
                return Err(AuthError::from_thrown(self.original.clone()));
            }
            if key == "pending" {
                self.release
                    .acquire()
                    .await
                    .map_err(|error| AuthError::internal(error.to_string()))?
                    .forget();
            }
            self.deleted.lock().expect("fixture lock").push(key.clone());
            if key == "pending" {
                self.completed.send(()).expect("completion receiver");
            }
            Ok(())
        }))
    }

    async fn get(&self, _: &str) -> AuthResult<Option<serde_json::Value>> {
        Err(AuthError::internal("Token deletion must not read storage"))
    }

    async fn set_native(&self, _: &FieldValue, _: &FieldValue, _: Option<f64>) -> AuthResult<()> {
        Err(AuthError::internal("Token deletion must not write storage"))
    }

    async fn delete(&self, _: &str) -> AuthResult<()> {
        Err(AuthError::internal(
            "Token deletion must invoke native storage",
        ))
    }

    async fn get_and_delete(&self, _: &str) -> AuthResult<Option<serde_json::Value>> {
        Err(AuthError::internal(
            "Token deletion must not consume verification storage",
        ))
    }
}

#[tokio::test]
async fn invocation_failure_stops_new_deletions_and_retains_started_peers() {
    for synchronous_failure in [false, true] {
        let (completed, mut completion) = mpsc::unbounded_channel();
        let original: FieldValue = FieldMap::from([
            ("kind".into(), "storage".into()),
            ("ownUndefined".into(), FieldValue::Undefined),
        ])
        .into();
        let storage = Arc::new(Storage {
            synchronous_failure,
            original: original.clone(),
            invoked: Mutex::default(),
            deleted: Mutex::default(),
            release: Semaphore::new(0),
            completed,
        });
        let result = delete_cached_tokens(
            storage.clone(),
            ["pending", "failure", "later"].map(String::from).to_vec(),
        )
        .await;
        assert!(result.as_ref().is_err_and(|error| {
            error
                .raw_value()
                .is_some_and(|value| value.strict_equals(&original))
        }));
        assert_eq!(
            *storage.invoked.lock().expect("fixture lock"),
            if synchronous_failure {
                vec!["pending", "failure"]
            } else {
                vec!["pending", "failure", "later"]
            },
        );
        assert_eq!(
            *storage.deleted.lock().expect("fixture lock"),
            if synchronous_failure {
                Vec::<String>::new()
            } else {
                vec!["later".into()]
            },
        );
        storage.release.add_permits(1);
        assert_eq!(
            tokio::time::timeout(std::time::Duration::from_secs(5), completion.recv())
                .await
                .expect("started deletion finishes"),
            Some(())
        );
        assert_eq!(
            *storage.deleted.lock().expect("fixture lock"),
            if synchronous_failure {
                vec!["pending"]
            } else {
                vec!["later", "pending"]
            },
        );
    }
}
