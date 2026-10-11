use super::super::{
    OAuthTokenSet, OAuthUserInfoRequest, generic_profile, resolved::ResolvedGenericOAuth,
};
use super::*;
use better_auth_core::{AuthConfig, store::EphemeralStore};

pub(super) async fn capture(scenario: Scenario) -> AuthResult<Value> {
    let state = State::new(scenario);
    let store = EphemeralStore::new(Arc::new(AuthConfig::new(SECRET).base_url(ORIGIN)));
    let before = capture::Before::capture(&state, &store)?;
    let callbacks = Arc::new(callbacks::Callbacks(state.clone()));
    let provider = ResolvedGenericOAuth {
        config: callbacks::generic(&callbacks),
        issuer: None,
        is_oidc: false,
        verifier: None,
    };
    let observed = state.clone();
    let observer: Arc<dyn Fn(&FieldValue) + Send + Sync> = Arc::new(move |value| {
        observed.tracking.lock().unwrap().info = Some(value.clone());
    });
    let result: AuthResult<FieldValue> = generic_profile::PROFILE_OBSERVER
        .scope(observer, async {
            let tokens = fields([("accessToken", ACCESS_TOKEN.into())]);
            let info = generic_profile::fetch_profile(
                &provider,
                &OAuthUserInfoRequest::from_fields(tokens.clone()),
                None,
            )
            .await
            .map_err(|error| match error {
                generic_profile::GenericProfileError::Profile(error)
                | generic_profile::GenericProfileError::Identity(error) => error,
            })?;
            let subject = generic_profile::resolve_account_subject(
                &provider,
                &OAuthTokenSet::from_fields(tokens),
                &info.model_property("data")?,
            )
            .await?;
            Ok(object([
                ("info", info),
                (
                    "accountKey",
                    object([
                        ("providerId", state.scenario.provider_id().into()),
                        ("accountId", subject),
                    ]),
                ),
            ]))
        })
        .await;
    let (value, outcome) = match result {
        Ok(value) => (value, json!({"returned": true, "kind": "native"})),
        Err(error) => {
            let mut outcome = json!({"returned": false});
            outcome.as_object_mut().unwrap().extend(
                observe::error_value(&error, &state)?
                    .as_object()
                    .unwrap()
                    .clone(),
            );
            (FieldValue::Undefined, outcome)
        }
    };
    before.finish(&state, &store, value, outcome, Value::Null)
}
