use super::*;
use axum::{
    Json, Router,
    extract::State as RequestState,
    http::{HeaderMap, Method, Uri},
    routing::post,
};

pub(super) struct TokenServer {
    pub url: String,
    task: tokio::task::JoinHandle<std::io::Result<()>>,
}

impl TokenServer {
    pub async fn new(state: Arc<State>) -> AuthResult<Self> {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .map_err(|error| {
                AuthError::internal(format!("Native profile token listener: {error}"))
            })?;
        let address = listener.local_addr().map_err(|error| {
            AuthError::internal(format!("Native profile token address: {error}"))
        })?;
        let router = Router::new().route("/token", post(token)).with_state(state);
        Ok(Self {
            url: format!("http://{address}/token"),
            task: tokio::spawn(async move { axum::serve(listener, router).await }),
        })
    }
}

impl Drop for TokenServer {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn token(
    RequestState(state): RequestState<Arc<State>>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    text: String,
) -> Json<Value> {
    assert_eq!(method, Method::POST);
    assert_eq!(uri.path_and_query().unwrap().as_str(), "/token");
    let body: serde_json::Map<String, Value> = url::form_urlencoded::parse(text.as_bytes())
        .map(|(key, value)| (key.into_owned(), value.into_owned().into()))
        .collect();
    assert_eq!(body["code"], "native-profile-code");
    state.remember(body["code_verifier"].as_str().unwrap(), "code-verifier");
    let mut observed = Vec::new();
    for (name, value) in &headers {
        match name.as_str() {
            // The transport adds these fields after the configured Request is constructed.
            "host" => {
                assert!(value.to_str().unwrap().starts_with("127.0.0.1:"));
            }
            "content-length" => {
                assert_eq!(
                    value.to_str().unwrap().parse::<usize>().unwrap(),
                    text.len()
                );
            }
            _ => observed.push((name.as_str().to_owned(), value.to_str().unwrap().to_owned())),
        }
    }
    observed.sort_by(|left, right| left.0.cmp(&right.0));
    state.log.event(
        json!({"kind": "token-http", "url": "https://oauth2.googleapis.com/token",
        "method": method.as_str(), "headers": observed, "body": body}),
    );
    Json(
        json!({"access_token": ACCESS_TOKEN, "id_token": ID_TOKEN, "scope": "profile", "expires_in": 3600}),
    )
}
