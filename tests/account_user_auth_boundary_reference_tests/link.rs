use super::*;
use better_auth_core::{
    AuthRequest, CreateSession, HttpMethod,
    id::{IdGeneration, IdGenerator},
};
use std::sync::atomic::{AtomicBool, Ordering};

#[path = "link/hooks.rs"]
mod hooks;
#[path = "link/observe.rs"]
mod observe;

const OWNER_TOKEN: &str = "link-owner-session-token";

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LinkCase {
    backend: String,
    scenario: String,
    joins: bool,
    setup: Option<fixture::Setup>,
    request: fixture::Request,
    before: Value,
    events: Vec<Value>,
    response: Option<fixture::Response>,
    native: Option<Value>,
    after: Value,
    checked: Value,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LinkFixture {
    version: String,
    scenarios: Vec<Scenario>,
    cases: Vec<LinkCase>,
}

fn options() -> AuthConfig {
    let mut config = config::baseline();
    config.session.disable_session_refresh = Some(true);
    config.advanced.database.generate_id =
        Some(IdGeneration::Custom(IdGenerator::new(|request| {
            Ok(Some(format!("zz-link-{}", request.model)))
        })));
    config
}

async fn seed<S: AuthSchema>(store: &Arc<dyn AuthStore<S>>, scenario: &Scenario) -> TestResult {
    let seed = store.with_runtime(Arc::new(options()), Vec::new(), Default::default())?;
    storage::seed(seed.as_ref(), scenario).await?;
    let date: FieldDate = "2030-01-02T03:04:05Z"
        .parse::<chrono::DateTime<chrono::Utc>>()?
        .into();
    let session = seed
        .create_session(CreateSession {
            inherited_fields: Default::default(),
            additional_fields: FieldMap::from([
                ("token".into(), OWNER_TOKEN.into()),
                ("createdAt".into(), date.clone().into()),
                ("updatedAt".into(), date.into()),
            ]),
            user_id: "user-a".into(),
            expires_at: "2100-01-02T03:04:05Z"
                .parse::<chrono::DateTime<chrono::Utc>>()?
                .into(),
            ip_address: Some(String::new()),
            user_agent: Some(String::new()),
            impersonated_by: None,
            active_organization_id: None,
        })
        .await?;
    assert_eq!(session.id, "zz-link-session");
    assert_eq!(session.token, OWNER_TOKEN);
    Ok(())
}

async fn native<S: AuthSchema>(
    auth: Arc<BetterAuth<S>>,
    input: &fixture::Request,
    hooks: &hooks::Hooks,
) -> TestResult<Value> {
    let url = url::Url::parse(&input.url)?;
    let path = url
        .path()
        .strip_prefix("/api/auth")
        .ok_or("Native fixture must use the auth base path")?
        .to_owned();
    let method = match input.method.as_str() {
        "GET" => HttpMethod::Get,
        "POST" => HttpMethod::Post,
        other => return Err(format!("Unexpected linking method: {other}").into()),
    };
    let headers = input
        .headers
        .iter()
        .cloned()
        .map(|[name, value]| (name, value))
        .collect();
    let body = (!input.body.is_null()).then(|| input.body.clone());
    let query = url.query().map(|_| {
        Value::Object(
            url.query_pairs()
                .map(|(name, value)| (name.into_owned(), Value::String(value.into_owned())))
                .collect(),
        )
    });
    let request = AuthRequest::from_parts(
        method.clone(),
        url.path().into(),
        headers,
        body.as_ref().map(serde_json::to_vec).transpose()?,
        query.clone(),
    )
    .with_url(url);
    let result = auth
        .call_endpoint(
            method,
            &path,
            better_auth::server_api::EndpointInput {
                headers: Some(request.headers.clone()),
                request: Some(request),
                body,
                query,
            },
        )
        .await;
    Ok(match result {
        Ok(response) => {
            json!({"rejected": false, "value": values::observe(&response.body.field_value()?)?,
            "status": values::observe(&response.native_status().field_value())?, "headers": hooks::header_state(&response.headers.into())?})
        }
        Err(error) => json!({"rejected": true, "error": hooks.observe_error(&error)?}),
    })
}

async fn contract<S: AuthSchema>(
    raw: Arc<dyn AuthStore<S>>,
    backend: storage::Backend<'_>,
    scenario: &Scenario,
    case: &LinkCase,
) -> TestResult {
    seed(&raw, scenario).await?;
    let before = backend.snapshot().await?;
    storage::assert_snapshot(&before, &case.before, backend.is_sqlite(), case);
    let events = Events::default();
    let hooks = Arc::new(hooks::Hooks::new(events.clone(), scenario)?);
    let mut config = config::configured(scenario, false, Some(&events))?;
    config.advanced.database.generate_id = options().advanced.database.generate_id;
    config.session.disable_session_refresh = Some(true);
    config.account.encrypt_oauth_tokens = Some(true);
    config.account.store_account_cookie = Some(true);
    let armed = Arc::new(AtomicBool::new(false));
    if scenario.mode == "lookup-api" {
        let field = config
            .account
            .additional_fields
            .get_mut("accountId")
            .ok_or("Account ID declaration missing")?;
        let recorded = events.clone();
        let failure = hooks.failure.clone();
        let armed = armed.clone();
        field
            .transform
            .as_mut()
            .ok_or("Account output transform missing")?
            .output = Some(better_auth_core::user_fields::UserFieldTransform::new(
            move |value| {
                recorded.push(json!({"kind": "output", "model": "account", "field": "accountId", "value": values::observe(&value)?}))?;
                if armed.load(Ordering::SeqCst) {
                    Err(AuthError::from_thrown(failure.clone()))
                } else {
                    Ok(value)
                }
            },
        ));
    }
    let store = raw.with_runtime(
        Arc::new(config.clone()),
        vec![hooks.clone()],
        Default::default(),
    )?;
    let harness = http::auth_with_hooks(
        store,
        config,
        scenario,
        &events,
        None,
        http::ContractHooks {
            after: Some(hooks.clone()),
            admission: Some(hooks.clone()),
            on_error: Some(hooks.clone()),
        },
    )
    .await?;
    let request = match (&harness.flow, &case.setup) {
        (Some(flow), Some(setup)) => {
            let request = flow
                .prepare(harness.auth.clone(), setup, &case.request)
                .await?;
            let _ = events.take()?;
            assert_eq!(backend.snapshot().await?, before);
            request
        }
        (None, None) => case.request.clone(),
        _ => return Err("Explicit linking setup must match the callback route".into()),
    };
    armed.store(true, Ordering::SeqCst);
    let start = chrono::Utc::now().timestamp_millis();
    let (mut response, mut native_result) = match scenario.invocation.as_str() {
        "http" => (
            Some(
                events
                    .capture(http::request(harness.auth, &request))
                    .await?,
            ),
            None,
        ),
        "native" => (
            None,
            Some(
                events
                    .capture(native(harness.auth, &request, &hooks))
                    .await?,
            ),
        ),
        other => return Err(format!("Unknown linking invocation: {other}").into()),
    };
    let end = chrono::Utc::now().timestamp_millis();
    let mut observed = events.take()?;
    if let Some(flow) = &harness.flow {
        flow.verify_and_normalize(&mut observed)?;
    }
    let mut after = backend.snapshot().await?;
    let anchors = observe::Anchors::verify(
        &observed,
        &before,
        &after,
        response.as_ref(),
        scenario,
        start..=end,
    )?;
    anchors.normalize_events(&mut observed)?;
    anchors.normalize_storage(&mut after)?;
    observe::assert_events(&observed, case, scenario)?;
    storage::assert_snapshot(&after, &case.after, backend.is_sqlite(), case);
    match (&mut response, &case.response) {
        (Some(actual), Some(expected)) => {
            anchors.normalize_response(actual);
            assert_eq!(actual.status, expected.status, "{case:?}");
            assert_eq!(actual.headers, expected.headers, "{case:?}");
            assert_eq!(actual.cookies, expected.cookies, "{case:?}");
            assert_eq!(actual.body, expected.body, "{case:?}");
        }
        (None, None) => {}
        _ => return Err("HTTP response must exist only for HTTP invocation".into()),
    }
    if let Some(native_result) = &mut native_result {
        assert_eq!(
            native_result["rejected"],
            scenario.callback || scenario.mode != "success"
        );
        if scenario.callback
            && matches!(
                scenario.mode.as_str(),
                "lookup-api" | "before-api" | "after-error"
            )
        {
            assert_eq!(native_result["error"]["sameObject"], true);
        }
        if !scenario.callback && scenario.mode == "before-api" {
            assert_eq!(native_result["error"]["statusCode"], 417);
            assert_eq!(native_result["error"]["sameObject"], false);
        }
        anchors.normalize(native_result);
    }
    assert_eq!(
        native_result, case.native,
        "{case:?}: native outcome must remain independent of HTTP materialization"
    );
    assert_eq!(
        case.checked,
        json!({"completeStorage": true, "completeHookKeys": true,
        "encryptedTokenVerified": anchors.encrypted_token, "ownerSessionUnchanged": true,
        "oauthStateAndCodeVerifierVerified": scenario.callback, "nativeInvocation": scenario.invocation == "native"})
    );
    Ok(())
}

#[tokio::test]
async fn oauth_explicit_linking_matches_upstream() -> TestResult {
    let fixture: LinkFixture = serde_json::from_str(include_str!(
        "../fixtures/account-user-auth-link-1.7.6.json"
    ))?;
    assert_eq!(fixture.version, "1.7.6");
    assert_eq!(fixture.scenarios.len(), 28);
    assert_eq!(fixture.cases.len(), 56);
    for scenario in &fixture.scenarios {
        assert!(scenario.linking);
        assert_eq!(scenario.relation, "default");
        for backend in ["memory", "sqlite"] {
            let cases: Vec<_> = fixture
                .cases
                .iter()
                .filter(|case| case.scenario == scenario.name && case.backend == backend)
                .collect();
            assert_eq!(cases.len(), 1, "{scenario:?}/{backend}");
            let case = cases[0];
            assert!(!case.joins);
            if backend == "memory" {
                let raw = Arc::new(EphemeralStore::new(Arc::new(config::baseline())));
                contract(
                    raw.clone(),
                    storage::Backend::Memory(raw.as_ref()),
                    scenario,
                    case,
                )
                .await?;
            } else {
                let database = storage::sqlite(scenario).await?;
                contract(
                    Arc::new(SeaOrmStore::<models::Core>::new(
                        config::baseline(),
                        database.clone(),
                    )),
                    storage::Backend::Sqlite(&database),
                    scenario,
                    case,
                )
                .await?;
            }
        }
    }
    Ok(())
}
