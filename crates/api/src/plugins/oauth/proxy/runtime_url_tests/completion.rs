use super::*;

#[tokio::test]
async fn completion_error_url_preserves_static_presence_and_runtime_origin() -> AuthResult<()> {
    use OptionUrl::{Auto, Dynamic, Static};

    for (name, option, runtime, error_url, expected) in [
        (
            "static wins",
            Static(ORIGIN),
            RUNTIME,
            None,
            "https://configured.proxy-runtime.test/api/auth/error",
        ),
        (
            "static path retained",
            Static("https://configured.proxy-runtime.test/tenant///"),
            RUNTIME,
            None,
            "https://configured.proxy-runtime.test/tenant/api/auth/error",
        ),
        (
            "static empty retained",
            Static(""),
            RUNTIME,
            None,
            "/api/auth/error",
        ),
        (
            "invalid static retained",
            Static("invalid"),
            RUNTIME,
            None,
            "invalid/api/auth/error",
        ),
        (
            "dynamic runtime origin",
            Dynamic,
            RUNTIME,
            None,
            "https://runtime.proxy-runtime.test/api/auth/error",
        ),
        (
            "absent runtime origin",
            Auto,
            RUNTIME,
            None,
            "https://runtime.proxy-runtime.test/api/auth/error",
        ),
        (
            "invalid runtime empty origin",
            Dynamic,
            "invalid",
            None,
            "/api/auth/error",
        ),
        (
            "opaque runtime empty origin",
            Dynamic,
            "data:text/plain,opaque",
            None,
            "/api/auth/error",
        ),
        (
            "empty runtime empty origin",
            Auto,
            "",
            None,
            "/api/auth/error",
        ),
        (
            "explicit error URL wins",
            Static(ORIGIN),
            RUNTIME,
            Some("/custom-error?retained=1"),
            "/custom-error?retained=1",
        ),
        (
            "empty error URL falls through",
            Static(ORIGIN),
            RUNTIME,
            Some(""),
            "https://configured.proxy-runtime.test/api/auth/error",
        ),
    ] {
        let fixture = Fixture::new(option, runtime, error_url);
        let mut request = AuthRequest::new(HttpMethod::Get, "/callback/test/oauth-proxy");
        request.query = Some(serde_json::json!({"callbackURL": "/complete"}));
        let response = OAuthProxyPlugin::new()
            .on_request(&request, &fixture.context)
            .await?
            .unwrap()
            .into_http_response()?;
        assert_eq!(response.status, 302, "{name}");
        assert_eq!(response.headers.iter().count(), 2, "{name}");
        assert_eq!(
            response.headers.get("content-type").map(String::as_str),
            Some("application/json"),
            "{name}"
        );
        let expected = format!(
            "{expected}{}error=missing_profile",
            if expected.contains('?') { '&' } else { '?' }
        );
        assert_eq!(response.headers.get("location"), Some(&expected), "{name}");
        assert!(response.body.bytes()?.is_empty(), "{name}");
        assert_eq!(
            *fixture.logs.0.lock().unwrap(),
            vec![(
                "error".into(),
                "OAuth proxy callback missing profile data".into(),
                vec![]
            )],
            "{name}",
        );
        fixture.assert_unchanged(option, runtime)?;
    }
    Ok(())
}
