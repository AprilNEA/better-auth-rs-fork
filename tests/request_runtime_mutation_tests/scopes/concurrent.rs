use super::*;
use better_auth::server_api::EndpointInput;
use better_auth_core::NativeRequest;
use std::{collections::HashMap, time::Duration};
use tokio::sync::Notify;

#[derive(Default)]
struct Peer {
    entered: Notify,
    release: Notify,
    finished: Notify,
    context: Mutex<Option<Arc<AuthContext<S>>>>,
}

#[derive(Clone, Default)]
struct Concurrent {
    peers: Arc<[Peer; 2]>,
    events: Arc<Mutex<Vec<String>>>,
}

impl Concurrent {
    async fn peer(
        &self,
        request: &AuthRequest,
        context: &AuthContext<S>,
    ) -> AuthResult<AuthResponse> {
        let index = request
            .header("x-peer")
            .expect("Peer header")
            .parse::<usize>()
            .expect("Peer fixture index");
        let peer = self.peers.get(index).expect("Peer fixture exists");
        let before = context.base_url();
        let retained = active(context);
        *lock(&peer.context)? = Some(retained.clone());
        context.set_base_url(changed(&format!("peer-{index}")));
        lock(&self.events)?.push(format!("start:{index}"));
        peer.entered.notify_one();
        peer.release.notified().await;
        assert!(Arc::ptr_eq(&active(context), &retained));
        assert_path("/runtime-peer");
        assert_eq!(context.base_url(), changed(&format!("peer-{index}")));
        lock(&self.events)?.push(format!("finish:{index}"));
        peer.finished.notify_one();
        AuthResponse::json(
            200,
            &json!({ "before": before, "after": context.base_url() }),
        )
    }

    async fn dispatch_peer(
        &self,
        context: &AuthContext<S>,
        index: usize,
    ) -> AuthResult<AuthResponse> {
        let headers = HashMap::from([("x-peer".into(), index.to_string())]);
        context
            .dispatch_native(
                NativeRequest {
                    request: None,
                    headers: Some(&headers),
                },
                AuthRoute::new(HttpMethod::Get, "/runtime-peer", "runtimePeer"),
                None,
                None,
                |request, context| async move { self.peer(&request, &context).await },
            )
            .await
    }
}

#[async_trait]
impl AuthPlugin<S> for Concurrent {
    fn name(&self) -> &'static str {
        "runtime-concurrent"
    }

    fn routes(&self) -> Vec<AuthRoute> {
        vec![
            AuthRoute::new(HttpMethod::Get, "/runtime-peer", "runtimePeer"),
            AuthRoute::new(HttpMethod::Get, "/runtime-concurrent", "runtimeConcurrent"),
        ]
    }

    async fn on_request(
        &self,
        request: &AuthRequest,
        context: &AuthContext<S>,
    ) -> AuthResult<Option<AuthResponse>> {
        match request.path() {
            "/runtime-peer" => self.peer(request, context).await.map(Some),
            "/runtime-concurrent" => {
                let retained = active(context);
                context.set_base_url(changed("parent"));
                let (first, second) = tokio::try_join!(
                    self.dispatch_peer(context, 0),
                    self.dispatch_peer(context, 1),
                )?;
                assert!(Arc::ptr_eq(&active(context), &retained));
                assert_path("/runtime-concurrent");
                assert_eq!(context.base_url(), changed("parent"));
                AuthResponse::json(200, &responses([first, second])?).map(Some)
            }
            _ => Ok(None),
        }
    }
}

fn responses(values: [AuthResponse; 2]) -> AuthResult<Value> {
    values
        .into_iter()
        .map(|response| {
            assert_eq!(response.status, 200);
            Ok(response
                .body
                .field_value()?
                .json()?
                .expect("Peer result is JSON"))
        })
        .collect::<AuthResult<Vec<_>>>()
        .map(Value::Array)
}

async fn root_peer(auth: &BetterAuth<S>, index: usize) -> AuthResult<AuthResponse> {
    auth.call_endpoint(
        HttpMethod::Get,
        "/runtime-peer",
        EndpointInput {
            headers: Some(HashMap::from([("x-peer".into(), index.to_string())])),
            ..Default::default()
        },
    )
    .await
}

#[tokio::test]
async fn concurrent_dispatches_isolate_writes_and_complete_in_reverse_release_order()
-> AuthResult<()> {
    for nested in [false, true] {
        let concurrent = Concurrent::default();
        let config = config();
        let store = store(&config)?;
        let auth = Arc::new(
            AuthBuilder::new(config)
                .store_arc(store.clone())
                .rate_limit(better_auth_core::middleware::RateLimitConfig::new().enabled(false))
                .plugin(concurrent.clone())
                .build()
                .await?,
        );
        let operation_auth = auth.clone();
        let mut operation = tokio::spawn(async move {
            if nested {
                let response = call(&operation_auth, "/runtime-concurrent", false).await?;
                assert_eq!(response.status, 200);
                Ok(response
                    .body
                    .field_value()?
                    .json()?
                    .expect("Concurrent result is JSON"))
            } else {
                let (first, second) =
                    tokio::try_join!(root_peer(&operation_auth, 0), root_peer(&operation_auth, 1))?;
                responses([first, second])
            }
        });
        let [first, second] = concurrent.peers.as_ref();
        let mut early = None;
        let observation = tokio::time::timeout(Duration::from_secs(5), async {
            tokio::select! {
                biased;
                _ = async { let _ = tokio::join!(first.entered.notified(), second.entered.notified()); } => {},
                result = &mut operation => {
                    early = Some(result);
                    return Err(AuthError::internal("Dispatch completed before both peers entered"));
                }
            }
            let first_context = lock(&first.context)?.clone().expect("First peer entered");
            let second_context = lock(&second.context)?.clone().expect("Second peer entered");
            let isolated = !Arc::ptr_eq(&first_context, &second_context)
                && !std::ptr::eq(first_context.as_ref(), auth.context())
                && !std::ptr::eq(second_context.as_ref(), auth.context());
            second.release.notify_one();
            tokio::select! {
                biased;
                () = second.finished.notified() => {},
                result = &mut operation => {
                    early = Some(result);
                    return Err(AuthError::internal("Dispatch completed before the first peer finished"));
                }
            }
            Ok(isolated)
        }).await;
        first.release.notify_one();
        second.release.notify_one();
        let result = match early {
            Some(result) => result,
            None => match tokio::time::timeout(Duration::from_secs(5), &mut operation).await {
                Ok(result) => result,
                Err(_) => {
                    operation.abort();
                    return Err(AuthError::internal(
                        "Concurrent dispatch did not finish within 5 seconds after releasing both peers",
                    ));
                }
            },
        }
        .expect("Concurrent operation task completed")?;
        assert!(observation.map_err(|_| AuthError::internal(
            "Concurrent peers did not reach their observation gates within 5 seconds",
        ))??);
        let before = if nested {
            changed("parent")
        } else {
            INITIAL_URL.into()
        };
        assert_eq!(
            result,
            json!([
                { "before": before, "after": changed("peer-0") },
                { "before": before, "after": changed("peer-1") },
            ])
        );
        let events = lock(&concurrent.events)?.clone();
        let mut starts = events
            .iter()
            .take(2)
            .map(String::as_str)
            .collect::<Vec<_>>();
        starts.sort_unstable();
        assert_eq!(starts, ["start:0", "start:1"]);
        assert_eq!(
            events
                .iter()
                .skip(2)
                .map(String::as_str)
                .collect::<Vec<_>>(),
            ["finish:1", "finish:0"]
        );
        assert_root(&auth, &store)?;
    }
    Ok(())
}
