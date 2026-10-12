use super::*;

#[tokio::test]
async fn completion_error_url_preserves_static_presence_and_runtime_origin() -> AuthResult<()> {
    use OptionUrl::{Auto, Dynamic, Static};

    for (name, option, runtime, error_url, expected, invalid) in [
        (
            "static wins",
            Static(ORIGIN),
            RUNTIME,
            None,
            "https://configured.proxy-runtime.test/api/auth/error",
            false,
        ),
        (
            "static path retained",
            Static("https://configured.proxy-runtime.test/tenant///"),
            RUNTIME,
            None,
            "https://configured.proxy-runtime.test/tenant/api/auth/error",
            false,
        ),
        (
            "static empty retained",
            Static(""),
            RUNTIME,
            None,
            "/api/auth/error",
            false,
        ),
        (
            "invalid static retained",
            Static("invalid"),
            RUNTIME,
            None,
            "invalid/api/auth/error",
            true,
        ),
        (
            "dynamic runtime origin",
            Dynamic,
            RUNTIME,
            None,
            "https://runtime.proxy-runtime.test/api/auth/error",
            false,
        ),
        (
            "absent runtime origin",
            Auto,
            RUNTIME,
            None,
            "https://runtime.proxy-runtime.test/api/auth/error",
            false,
        ),
        (
            "invalid runtime empty origin",
            Dynamic,
            "invalid",
            None,
            "/api/auth/error",
            false,
        ),
        (
            "opaque runtime empty origin",
            Dynamic,
            "data:text/plain,opaque",
            None,
            "/api/auth/error",
            false,
        ),
        (
            "empty runtime empty origin",
            Auto,
            "",
            None,
            "/api/auth/error",
            false,
        ),
        (
            "explicit error URL wins",
            Static(ORIGIN),
            RUNTIME,
            Some("/custom-error?retained=1"),
            "/custom-error?retained=1",
            false,
        ),
        (
            "empty error URL falls through",
            Static(ORIGIN),
            RUNTIME,
            Some(""),
            "https://configured.proxy-runtime.test/api/auth/error",
            false,
        ),
    ] {
        let fixture = Fixture::new(option, runtime, error_url);
        let mut request = AuthRequest::new(HttpMethod::Get, "/callback/test/oauth-proxy");
        request.query = Some(serde_json::json!({"callbackURL": "/complete"}));
        let root_config = Arc::new((*fixture.context.config).clone().base_url(ORIGIN));
        let root = AuthContext::new(root_config, fixture.store.clone())
            .initialize_request_context()
            .await?;
        let desired_config = fixture.context.config.clone();
        let request_ref = &request;
        let response = root
            .with_http_context(&request, |context| async move {
                let mut context = (*context).clone();
                context.config = desired_config;
                context.set_base_url(runtime);
                match OAuthProxyPlugin::new()
                    .on_request(request_ref, &context)
                    .await
                {
                    Ok(response) => response.unwrap().into_http_response(),
                    Err(error) => {
                        assert!(invalid, "{name}: {error}");
                        assert!(matches!(&error, AuthError::TypeError(_)), "{name}");
                        assert_eq!(error.to_string(), "Invalid URL", "{name}");
                        better_auth_core::api_error::handle_http_error(error, &context).await
                    }
                }
            })
            .await?;
        assert_eq!(response.status, if invalid { 500 } else { 302 }, "{name}");
        assert_eq!(
            response.headers.iter().count(),
            if invalid { 0 } else { 2 },
            "{name}"
        );
        assert_eq!(
            response.headers.get("content-type").map(String::as_str),
            (!invalid).then_some("application/json"),
            "{name}"
        );
        let expected = format!(
            "{expected}{}error=missing_profile",
            if expected.contains('?') { '&' } else { '?' }
        );
        assert_eq!(
            response.headers.get("location"),
            (!invalid).then_some(&expected),
            "{name}"
        );
        assert!(response.body.bytes()?.is_empty(), "{name}");
        let mut expected_logs = vec![(
            "error".into(),
            "OAuth proxy callback missing profile data".into(),
            vec![],
        )];
        if invalid {
            expected_logs.push((
                "error".into(),
                "TypeError".into(),
                vec!["Invalid URL".into()],
            ));
        }
        assert_eq!(*fixture.logs.0.lock().unwrap(), expected_logs, "{name}",);
        assert_eq!(root.base_url(), format!("{ORIGIN}/custom-auth"), "{name}");
        assert_eq!(root.config.base_url.as_static(), Some(ORIGIN), "{name}");
        fixture.assert_unchanged(option, runtime)?;
    }
    Ok(())
}
