use crate::store::{EphemeralStore, StatelessSchema};
use crate::{AuthConfig, AuthContext};
use std::sync::Arc;

#[tokio::test]
async fn initialization_retains_the_source_url_cell_and_explicit_assignments() {
    for assigned in [None, Some("http://assigned.runtime.test/custom")] {
        let config = Arc::new(
            AuthConfig::new("runtime-ownership-secret-at-least-32-characters")
                .base_url("https://initial.runtime.test"),
        );
        let source = AuthContext::<StatelessSchema>::new(
            config.clone(),
            Arc::new(EphemeralStore::new(config)),
        );
        let source_clone = source.clone();
        if let Some(assigned) = assigned {
            source_clone.set_base_url(assigned);
        }

        let first = source
            .initialize_request_context()
            .await
            .expect("Source initializes");
        let second = source_clone
            .initialize_request_context()
            .await
            .expect("Source clone initializes");
        let expected = assigned.unwrap_or("https://initial.runtime.test/api/auth");
        for context in [&source, &source_clone, first.as_ref(), second.as_ref()] {
            assert_eq!(context.base_url(), expected);
        }

        first.set_base_url("http://updated.runtime.test/shared");
        let repeated = source
            .initialize_request_context()
            .await
            .expect("Repeated initialization retains the live runtime URL");
        for context in [
            &source,
            &source_clone,
            first.as_ref(),
            second.as_ref(),
            repeated.as_ref(),
        ] {
            assert_eq!(context.base_url(), "http://updated.runtime.test/shared");
        }

        source_clone.set_base_url("http://source.runtime.test/shared");
        for context in [first.as_ref(), second.as_ref(), repeated.as_ref()] {
            assert_eq!(context.base_url(), "http://source.runtime.test/shared");
        }
    }
}
