//! Paired with contracts/oauth-proxy-runtime-url.test.ts at the proxy callback boundaries.

#![expect(
    clippy::unwrap_used,
    clippy::panic_in_result_fn,
    reason = "Contract assertions preserve exact callback results, errors, logs, and storage."
)]

use std::sync::{Arc, Mutex};

use better_auth_core::{
    AuthConfig, AuthContext, AuthError, AuthPlugin, AuthRequest, AuthResponse, AuthResult, BaseUrl,
    DynamicBaseUrl, FieldDate, FieldMap, FieldValue, HttpMethod,
    observability::logger::{LogArgument, LogLevel, LogSink, LoggerConfig},
    store::{EphemeralStore, StatelessSchema, schema::EntityRole},
};

use super::{OAuthProxyConfig, OAuthProxyPlugin};

mod completion;

const ORIGIN: &str = "https://configured.proxy-runtime.test";
const RUNTIME: &str = "https://runtime.proxy-runtime.test/custom/auth";
const PRODUCTION: &str = "https://production.proxy-runtime.test";
const SECRET: &str = "oauth-proxy-runtime-secret-at-least-thirty-two-characters";
const WARNING: &str = "OAuth proxy: cross-origin callback reached after hook unexpectedly";

#[derive(Clone, Copy)]
enum OptionUrl {
    Static(&'static str),
    Dynamic,
    Auto,
}

#[derive(Default)]
struct Logs(Mutex<Vec<(String, String, Vec<String>)>>);

impl LogSink for Logs {
    fn log(&self, level: LogLevel, message: LogArgument<'_>, arguments: &[LogArgument<'_>]) {
        self.0.lock().unwrap().push((
            level.as_str().into(),
            message.to_string(),
            arguments.iter().map(ToString::to_string).collect(),
        ));
    }
}

struct Fixture {
    context: AuthContext<StatelessSchema>,
    store: Arc<EphemeralStore>,
    logs: Arc<Logs>,
}

impl Fixture {
    fn new(option: OptionUrl, runtime: &str, error_url: Option<&str>) -> Self {
        let logs = Arc::new(Logs::default());
        let mut config = AuthConfig::new(SECRET);
        config.base_url = match option {
            OptionUrl::Static(value) => BaseUrl::Static(value.into()),
            OptionUrl::Dynamic => BaseUrl::Dynamic(DynamicBaseUrl {
                allowed_hosts: vec!["*.proxy-runtime.test".into()],
                fallback: None,
                protocol: None,
            }),
            OptionUrl::Auto => BaseUrl::Auto,
        };
        config.base_path = "/custom-auth".into();
        config.api_error.error_url = error_url.map(str::to_owned);
        config.logger = LoggerConfig {
            log: Some(logs.clone()),
            ..Default::default()
        };
        let config = Arc::new(config);
        let store = Arc::new(EphemeralStore::new(config.clone()));
        let context = AuthContext::new(config, store.clone());
        context.set_base_url(runtime);
        Self {
            context,
            store,
            logs,
        }
    }

    fn assert_unchanged(&self, option: OptionUrl, runtime: &str) -> AuthResult<()> {
        assert_eq!(self.context.base_url(), runtime);
        assert_eq!(
            self.context.config.base_url.as_static(),
            match option {
                OptionUrl::Static(value) => Some(value),
                OptionUrl::Dynamic | OptionUrl::Auto => None,
            }
        );
        for role in [
            EntityRole::User,
            EntityRole::Session,
            EntityRole::Account,
            EntityRole::Verification,
        ] {
            assert!(self.store.storage_rows(role)?.is_empty(), "{role:?}");
        }
        Ok(())
    }
}

#[derive(Clone, Copy)]
enum CallbackOutcome {
    Keep,
    Warn,
    Rewrite(&'static str),
    Invalid,
}

fn redirected(base: &str, query: &str) -> Option<String> {
    Some(format!("{base}/oauth-proxy?callbackURL={query}"))
}

#[tokio::test]
async fn callback_runtime_url_precedence_guards_errors_and_complete_response() -> AuthResult<()> {
    use CallbackOutcome::{Invalid, Keep, Rewrite, Warn};
    use OptionUrl::{Auto, Dynamic, Static};

    for (name, option, runtime, production, location, outcome) in [
        (
            "production wins",
            Static(ORIGIN),
            RUNTIME,
            Some(PRODUCTION),
            redirected(PRODUCTION, "%2Fcomplete"),
            Rewrite("/complete"),
        ),
        (
            "static wins",
            Static(ORIGIN),
            RUNTIME,
            None,
            redirected(ORIGIN, "%2Fcomplete"),
            Rewrite("/complete"),
        ),
        (
            "empty production uses static",
            Static(ORIGIN),
            RUNTIME,
            Some(""),
            redirected(ORIGIN, "%2Fcomplete"),
            Rewrite("/complete"),
        ),
        (
            "empty static uses runtime",
            Static(""),
            RUNTIME,
            None,
            redirected(RUNTIME, "%2Fcomplete"),
            Rewrite("/complete"),
        ),
        (
            "dynamic uses runtime",
            Dynamic,
            RUNTIME,
            None,
            redirected(RUNTIME, "%2Fcomplete"),
            Rewrite("/complete"),
        ),
        (
            "absent uses runtime",
            Auto,
            RUNTIME,
            None,
            redirected(RUNTIME, "%2Fcomplete"),
            Rewrite("/complete"),
        ),
        (
            "invalid production warns",
            Static(ORIGIN),
            RUNTIME,
            Some("invalid"),
            redirected(ORIGIN, "%2Fcomplete"),
            Warn,
        ),
        (
            "invalid static wins",
            Static("invalid"),
            RUNTIME,
            None,
            redirected(RUNTIME, "%2Fcomplete"),
            Warn,
        ),
        (
            "invalid runtime warns",
            Dynamic,
            "invalid",
            None,
            redirected(ORIGIN, "%2Fcomplete"),
            Warn,
        ),
        (
            "cross origin warns",
            Static(ORIGIN),
            RUNTIME,
            None,
            redirected(PRODUCTION, "%2Fcomplete"),
            Warn,
        ),
        (
            "missing location",
            Static(ORIGIN),
            RUNTIME,
            None,
            None,
            Keep,
        ),
        (
            "missing marker",
            Static(ORIGIN),
            RUNTIME,
            None,
            Some(format!("{ORIGIN}/complete")),
            Keep,
        ),
        (
            "relative location",
            Static(ORIGIN),
            RUNTIME,
            None,
            Some("/oauth-proxy?callbackURL=%2Fcomplete".into()),
            Keep,
        ),
        (
            "uppercase scheme",
            Static(ORIGIN),
            RUNTIME,
            None,
            redirected("HTTPS://configured.proxy-runtime.test", "%2Fcomplete"),
            Keep,
        ),
        (
            "non-http scheme",
            Static(ORIGIN),
            RUNTIME,
            None,
            redirected("ftp://configured.proxy-runtime.test", "%2Fcomplete"),
            Keep,
        ),
        (
            "invalid location throws",
            Static("invalid"),
            RUNTIME,
            None,
            Some("http://[/oauth-proxy?callbackURL=%2Fcomplete".into()),
            Invalid,
        ),
        (
            "empty callback stays",
            Static(ORIGIN),
            RUNTIME,
            None,
            redirected(ORIGIN, ""),
            Keep,
        ),
        (
            "first empty callback stays",
            Static(ORIGIN),
            RUNTIME,
            None,
            redirected(ORIGIN, "&callbackURL=%2Fsecond"),
            Keep,
        ),
        (
            "first callback wins",
            Static(ORIGIN),
            RUNTIME,
            None,
            redirected(ORIGIN, "%2Ffirst&callbackURL=%2Fsecond"),
            Rewrite("/first"),
        ),
        (
            "legacy marker",
            Static(ORIGIN),
            RUNTIME,
            None,
            Some(format!(
                "{ORIGIN}/oauth-proxy-callback?callbackURL=%2Fcomplete"
            )),
            Rewrite("/complete"),
        ),
        (
            "opaque http prefix warns",
            Static("invalid"),
            RUNTIME,
            None,
            Some("http+opaque:body/oauth-proxy?callbackURL=%2Fcomplete".into()),
            Warn,
        ),
    ] {
        let fixture = Fixture::new(option, runtime, None);
        let proxy = OAuthProxyPlugin::with_config(OAuthProxyConfig {
            production_url: production.map(str::to_owned),
            ..Default::default()
        });
        let child: FieldValue =
            FieldMap::from([("date".into(), FieldDate::invalid().into())]).into();
        let original: FieldValue = FieldMap::from([
            ("kept".into(), FieldValue::Undefined),
            ("child".into(), child.clone()),
        ])
        .into();
        let mut response =
            AuthResponse::native(Some(201), original.clone()).with_header("x-proxy", "kept");
        if let Some(location) = &location {
            let _ = response.headers.insert("location", location.clone());
        }
        let result = proxy
            .after_request(
                &AuthRequest::new(HttpMethod::Get, "/callback/test"),
                &mut response,
                &fixture.context,
            )
            .await;
        if matches!(outcome, Invalid) {
            assert!(
                matches!(result, Err(AuthError::TypeError(_))),
                "{name}: {result:?}"
            );
        } else {
            result?;
        }
        let returned = response.body.field_value()?;
        assert!(returned.strict_equals(&original), "{name}");
        assert!(
            returned.model_property("child")?.strict_equals(&child),
            "{name}"
        );
        assert_eq!(
            returned.as_object().unwrap().own_keys()?,
            ["kept", "child"],
            "{name}"
        );
        assert_eq!(response.native_status(), Some(201).into(), "{name}");
        let expected = match outcome {
            Rewrite(value) => Some(value),
            Keep | Warn | Invalid => location.as_deref(),
        };
        assert_eq!(
            response.headers.get("location").map(String::as_str),
            expected,
            "{name}"
        );
        assert_eq!(
            response.headers.get("x-proxy").map(String::as_str),
            Some("kept"),
            "{name}"
        );
        assert_eq!(
            response.headers.iter().count(),
            1 + usize::from(location.is_some()),
            "{name}"
        );
        assert_eq!(
            *fixture.logs.0.lock().unwrap(),
            if matches!(outcome, Warn) {
                vec![("warn".into(), WARNING.into(), vec![])]
            } else {
                vec![]
            },
            "{name}",
        );
        fixture.assert_unchanged(option, runtime)?;
    }
    Ok(())
}

#[test]
fn skip_distinguishes_empty_url_from_nonempty_invalid_origins() {
    assert!(
        std::env::var("BETTER_AUTH_URL")
            .unwrap_or_default()
            .is_empty()
    );
    for (runtime, current, expected) in [
        ("", "invalid-current", false),
        ("invalid-runtime", "invalid-current", true),
        ("data:text/plain,runtime", "data:text/plain,current", true),
        ("invalid-runtime", ORIGIN, false),
    ] {
        let fixture = Fixture::new(OptionUrl::Auto, runtime, None);
        let config = OAuthProxyConfig {
            current_url: Some(current.into()),
            ..Default::default()
        };
        assert_eq!(
            config.skip_proxy(
                &AuthRequest::new(HttpMethod::Post, "/sign-in/social"),
                &fixture.context
            ),
            expected
        );
    }
}
