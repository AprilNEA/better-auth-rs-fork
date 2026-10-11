use super::super::{callback, generic_profile};
use super::*;
use better_auth_core::{
    AuthPlugin, AuthRequest, AuthResponse, Headers, HttpMethod, store::StatelessSchema,
};
use harness::Harness;

fn request(method: HttpMethod, path: &str) -> AuthRequest {
    let mut request = AuthRequest::new(method, path);
    request.headers = HashMap::from([
        ("origin".into(), ORIGIN.into()),
        ("user-agent".into(), "native-profile-contract".into()),
    ]);
    request
}

impl Harness {
    async fn dispatch(&self, request: AuthRequest, state: &State) -> AuthResult<AuthResponse> {
        let is_callback = request.path.starts_with("/callback/");
        let route = AuthPlugin::<StatelessSchema>::routes(&self.plugin)
            .into_iter()
            .find(|route| route.matches(request.method(), request.path()))
            .unwrap();
        self.dispatcher
            .native(request, route, &self.context, |request| async move {
                if is_callback {
                    callback::handle_callback(
                        self.plugin.resolved_config().await?,
                        state.scenario.provider_id(),
                        &request,
                        &self.context,
                    )
                    .await
                } else {
                    self.plugin
                        .on_request(&request, &self.context)
                        .await?
                        .ok_or_else(|| AuthError::internal("Native profile endpoint did not match"))
                }
            })
            .await
    }

    async fn invoke(&self, state: &State) -> AuthResult<AuthResponse> {
        if state.scenario.operation == "account-info" {
            let mut request =
                AuthRequest::new(HttpMethod::Get, "/account-info").with_optional_headers(None);
            request.query = Some(json!({"accountId": "stored-account", "userId": "owner"}));
            return self.dispatch(request, state).await;
        }
        let mut signin = request(HttpMethod::Post, "/sign-in/social");
        let body = if state.scenario.operation == "direct" {
            json!({"provider": state.scenario.provider_id(), "idToken": {
                "token": ID_TOKEN, "nonce": "native-profile-nonce", "accessToken": ACCESS_TOKEN,
            }})
        } else {
            assert_eq!(state.scenario.operation, "callback");
            json!({"provider": state.scenario.provider_id(), "callbackURL": format!("{ORIGIN}/complete"),
                "errorCallbackURL": format!("{ORIGIN}/failed"), "disableRedirect": true})
        };
        signin.body = Some(serde_json::to_vec(&body)?);
        let started = self.dispatch(signin, state).await?;
        if state.scenario.operation == "direct" {
            return Ok(started);
        }
        let url = started.body.field_value()?.model_property("url")?;
        let url = url::Url::parse(url.as_str().unwrap()).unwrap();
        let state_id = url
            .query_pairs()
            .find(|(key, _)| key == "state")
            .unwrap()
            .1
            .into_owned();
        state.remember(&state_id, "oauth-state");
        let mut callback = request(
            HttpMethod::Get,
            &format!("/callback/{}", state.scenario.provider_id()),
        );
        callback.headers.insert(
            "cookie".into(),
            started
                .headers
                .get_all("set-cookie")
                .map(|cookie| cookie.split(';').next().unwrap())
                .collect::<Vec<_>>()
                .join("; "),
        );
        callback.query = Some(json!({"code": "native-profile-code", "state": state_id}));
        match self.dispatch(callback, state).await {
            Ok(response) => response.into_http_response(),
            Err(error) if error.is_api_error()? => error.to_auth_response().into_http_response(),
            Err(error) => Err(error),
        }
    }
}

pub(super) async fn capture(scenario: Scenario) -> AuthResult<Value> {
    let state = State::new(scenario);
    let sample = Harness::new(&state).await?;
    let before = capture::Before::capture(&state, &sample.store)?;
    let observed = state.clone();
    let observer: Arc<dyn Fn(&FieldValue) + Send + Sync> = Arc::new(move |value| {
        observed.tracking.lock().unwrap().info = Some(value.clone());
    });
    let result = generic_profile::PROFILE_OBSERVER
        .scope(observer, sample.invoke(&state))
        .await;
    let (value, outcome, observed_headers) = match result {
        Ok(response) => {
            let headers = headers::observe(Some(&response.headers), &state);
            if state.scenario.operation == "callback" {
                (
                    FieldValue::Undefined,
                    json!({"returned": true, "kind": "http", "status": response.status,
                    "body": String::from_utf8(response.body.bytes()?.into_owned()).unwrap()}),
                    headers,
                )
            } else {
                (
                    response.body.field_value()?,
                    json!({"returned": true, "kind": "native"}),
                    headers,
                )
            }
        }
        Err(error) => {
            let mut outcome = json!({"returned": false});
            outcome.as_object_mut().unwrap().extend(
                observe::error_value(&error, &state)?
                    .as_object()
                    .unwrap()
                    .clone(),
            );
            let explicit = error.headers_value()?;
            let headers = if explicit.is_truthy() {
                Some(Headers::from_field_value(&explicit)?)
            } else {
                None
            };
            (
                FieldValue::Undefined,
                outcome,
                headers::observe(headers.as_ref(), &state),
            )
        }
    };
    before.finish(&state, &sample.store, value, outcome, observed_headers)
}
