use super::*;
use better_auth_core::{
    BaseUrl, BaseUrlProtocol, CrossSubDomainConfig, DynamicBaseUrl, SameSite, TrustedValues,
    TrustedValuesResolver,
};

fn policy(context: &AuthContext<S>) -> AuthResult<Value> {
    let cookie = context.create_auth_cookie("runtime", Default::default())?;
    let attributes = cookie.attributes;
    assert_eq!(attributes.partitioned, None);
    assert_eq!(attributes.max_age, None);
    assert_eq!(attributes.expires, None);
    assert_eq!(attributes.same_site, Some(SameSite::Lax));
    Ok(json!({
        "baseURL": context.base_url(),
        "optionURL": context.config.base_url.as_static(), "optionPath": context.config.base_path,
        "origins": context.trusted_origins(), "providers": context.trusted_providers(),
        "cookie": {"name": cookie.name, "attributes": {
            "secure": attributes.secure, "sameSite": "lax", "path": attributes.path,
            "httpOnly": attributes.http_only, "domain": attributes.domain,
        }},
    }))
}

#[derive(Clone, Default)]
struct Capture {
    observations: Arc<Mutex<Vec<Value>>>,
    outer: Arc<Mutex<Option<Arc<AuthContext<S>>>>>,
    endpoint: Arc<Mutex<Option<Arc<AuthContext<S>>>>>,
}

impl Capture {
    fn record(&self, phase: &str, context: &AuthContext<S>) -> AuthResult<()> {
        let mut value = policy(context)?;
        value["phase"] = phase.into();
        lock(&self.observations)?.push(value);
        Ok(())
    }
    fn endpoint(&self, context: &AuthContext<S>) -> AuthResult<()> {
        assert!(Arc::ptr_eq(
            &active(context),
            lock(&self.endpoint)?.as_ref().expect("Endpoint retained")
        ));
        Ok(())
    }
}

#[async_trait]
impl BeforeEndpointHook<S> for Capture {
    async fn before(
        &self,
        _: &AuthRequest,
        context: &AuthContext<S>,
    ) -> AuthResult<Option<BeforeRequestAction>> {
        let endpoint = active(context);
        let outer = lock(&self.outer)?.clone().expect("HTTP context retained");
        assert!(!Arc::ptr_eq(&endpoint, &outer));
        assert!(Arc::ptr_eq(&endpoint.config, &outer.config));
        assert!(std::ptr::eq(
            endpoint.trusted_origins().as_ptr(),
            outer.trusted_origins().as_ptr()
        ));
        assert!(std::ptr::eq(
            endpoint.trusted_providers().as_ptr(),
            outer.trusted_providers().as_ptr()
        ));
        *lock(&self.endpoint)? = Some(endpoint);
        self.record("before", context)?;
        context.set_base_url(changed("endpoint"));
        Ok(None)
    }
}

#[async_trait]
impl AfterEndpointHook<S> for Capture {
    async fn after(
        &self,
        _: &AuthRequest,
        _: &mut AuthResponse,
        context: &AuthContext<S>,
    ) -> AuthResult<()> {
        self.endpoint(context)?;
        self.record("after", context)?;
        context.set_base_url(changed("endpoint-after"));
        Ok(())
    }
}

#[async_trait]
impl AuthPlugin<S> for Capture {
    fn name(&self) -> &'static str {
        "runtime-http"
    }
    fn routes(&self) -> Vec<AuthRoute> {
        vec![AuthRoute::get("/runtime-http", "runtimeHTTP")]
    }
    async fn on_http_request(
        &self,
        _: &AuthRequest,
        context: &AuthContext<S>,
    ) -> AuthResult<Option<AuthResponse>> {
        *lock(&self.outer)? = Some(active(context));
        self.record("onRequest", context)?;
        context.set_base_url(changed("http"));
        Ok(None)
    }
    async fn on_request(
        &self,
        _: &AuthRequest,
        context: &AuthContext<S>,
    ) -> AuthResult<Option<AuthResponse>> {
        self.endpoint(context)?;
        Ok(Some(AuthResponse::json(200, &policy(context)?)?))
    }
    async fn on_http_response(
        &self,
        _: &AuthRequest,
        _: &mut AuthResponse,
        context: &AuthContext<S>,
    ) -> AuthResult<Option<AuthResponse>> {
        assert!(Arc::ptr_eq(
            &active(context),
            lock(&self.outer)?.as_ref().expect("HTTP context retained")
        ));
        self.record("onResponse", context)?;
        context.set_base_url(changed("response"));
        Ok(None)
    }
}

struct FollowingResponse(Capture);
#[async_trait]
impl AuthPlugin<S> for FollowingResponse {
    fn name(&self) -> &'static str {
        "runtime-http-response-observer"
    }
    fn routes(&self) -> Vec<AuthRoute> {
        vec![]
    }
    async fn on_request(
        &self,
        _: &AuthRequest,
        _: &AuthContext<S>,
    ) -> AuthResult<Option<AuthResponse>> {
        Ok(None)
    }
    async fn on_http_response(
        &self,
        _: &AuthRequest,
        _: &mut AuthResponse,
        context: &AuthContext<S>,
    ) -> AuthResult<Option<AuthResponse>> {
        assert!(Arc::ptr_eq(
            &active(context),
            lock(&self.0.outer)?
                .as_ref()
                .expect("HTTP context retained")
        ));
        self.0.record("following-onResponse", context)?;
        Ok(None)
    }
}

struct Trust {
    phase: &'static str,
    events: Arc<Mutex<Vec<String>>>,
    value: &'static str,
}
#[async_trait]
impl TrustedValuesResolver for Trust {
    async fn resolve(&self, request: Option<&AuthRequest>) -> AuthResult<Vec<String>> {
        lock(&self.events)?.push(format!(
            "{}:{}",
            self.phase,
            request
                .and_then(AuthRequest::url)
                .map_or("none", |url| url.as_str())
        ));
        Ok(vec![self.value.into()])
    }
}

#[tokio::test]
async fn http_runtime_writes_preserve_routing_configuration_trust_and_cookies() -> AuthResult<()> {
    for dynamic in [false, true] {
        let capture = Capture::default();
        let resolutions = Arc::new(Mutex::new(Vec::new()));
        let mut config = config();
        if dynamic {
            config.base_url = BaseUrl::Dynamic(DynamicBaseUrl {
                allowed_hosts: vec!["preview.runtime.test".into()],
                fallback: None,
                protocol: Some(BaseUrlProtocol::Https),
            });
        }
        config.advanced.cross_sub_domain_cookies = Some(CrossSubDomainConfig {
            enabled: Some(true),
            ..Default::default()
        });
        config.trusted_origins = Some(TrustedValues::Dynamic(Arc::new(Trust {
            phase: "origins",
            events: resolutions.clone(),
            value: "https://trusted.runtime.test",
        })));
        config.account.account_linking.trusted_providers =
            Some(TrustedValues::Dynamic(Arc::new(Trust {
                phase: "providers",
                events: resolutions.clone(),
                value: "google",
            })));
        let store = store(&config)?;
        let auth = AuthBuilder::new(config)
            .store_arc(store.clone())
            .rate_limit(better_auth_core::middleware::RateLimitConfig::new().enabled(false))
            .hooks(EndpointHooks {
                before: Some(Arc::new(capture.clone())),
                after: Some(Arc::new(capture.clone())),
            })
            .plugin(capture.clone())
            .plugin(FollowingResponse(capture.clone()))
            .build()
            .await?;
        let expected = json!({
            "baseURL": changed("endpoint"), "optionURL": ORIGIN, "optionPath": BASE_PATH,
            "origins": [ORIGIN, "https://trusted.runtime.test"], "providers": ["google"],
            "cookie": {"name": "__Secure-better-auth.runtime", "attributes": {
                "secure": true, "sameSite": "lax", "path": "/", "httpOnly": true,
                "domain": "preview.runtime.test",
            }},
        });
        for _ in 0..2 {
            let response = call(&auth, "/runtime-http", true).await?;
            assert_eq!(response.status, 200);
            assert_eq!(response.body.json()?, Some(expected.clone()));
            assert_eq!(
                lock(&capture.endpoint)?
                    .as_ref()
                    .expect("Endpoint retained")
                    .base_url(),
                changed("endpoint-after")
            );
            assert_eq!(
                lock(&capture.outer)?
                    .as_ref()
                    .expect("HTTP context retained")
                    .base_url(),
                changed("response")
            );
            assert_eq!(
                auth.context().base_url(),
                if dynamic { "" } else { INITIAL_URL }
            );
            assert!(auth.context().current_request_context().is_none());
            assert!(better_auth_core::hooks::current_request_hook_context().is_none());
        }
        let expected_observations: Vec<_> = (0..2)
            .flat_map(|_| {
                [
                    ("onRequest", INITIAL_URL.to_owned()),
                    ("before", changed("http")),
                    ("after", changed("endpoint")),
                    ("onResponse", changed("http")),
                    ("following-onResponse", changed("response")),
                ]
            })
            .map(|(phase, url)| {
                let mut value = expected.clone();
                value["phase"] = phase.into();
                value["baseURL"] = url.into();
                value
            })
            .collect();
        assert_eq!(*lock(&capture.observations)?, expected_observations);
        let request_url = format!("{INITIAL_URL}/runtime-http");
        assert_eq!(
            *lock(&resolutions)?,
            [
                "origins:none".into(),
                "providers:none".into(),
                format!("origins:{request_url}"),
                format!("providers:{request_url}"),
                format!("origins:{request_url}"),
                format!("providers:{request_url}"),
            ]
        );
        assert_eq!(snapshot(&store)?, empty_database());
    }
    Ok(())
}
