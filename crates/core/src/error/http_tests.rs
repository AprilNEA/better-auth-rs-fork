#![expect(
    clippy::unwrap_used,
    clippy::panic,
    clippy::panic_in_result_fn,
    reason = "The paired HTTP logging contract checks native identities, exact event order, and complete responses."
)]

use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, Ordering},
};

use crate::{
    AuthError, AuthResult, FieldMap, FieldObject, FieldValue,
    api_error::{ApiErrorHandler, ApiErrorTask},
    observability::LogLevel,
};

mod message;
mod observers;

use observers::{Events, Harness, Probe, S, assert_empty_response};

fn error_source(
    events: &Events,
    name: Option<FieldValue>,
    message: &str,
    failure: Option<&'static str>,
    replacement: &FieldValue,
) -> FieldValue {
    let mut fields = FieldMap::from([("message".into(), message.into())]);
    if let Some(name) = name {
        let _ = fields.insert("name".into(), name);
    }
    let fields = FieldObject::from(fields);
    let logging = Arc::new(AtomicBool::new(false));
    let selected_name = Arc::new(AtomicBool::new(false));
    Probe::value(
        fields.clone(),
        {
            let events = events.clone();
            let fields = fields.clone();
            let logging = logging.clone();
            let selected_name = selected_name.clone();
            move |name| {
                if matches!(name, "message" | "name") {
                    events.lock().unwrap().push(format!("has:{name}"));
                }
                if name == "message" {
                    logging.store(true, Ordering::Relaxed);
                }
                if name == "name" && logging.load(Ordering::Relaxed) {
                    selected_name.store(true, Ordering::Relaxed);
                }
                fields.has_property(name)
            }
        },
        {
            let events = events.clone();
            let replacement = replacement.clone();
            move |name| {
                if matches!(name, "message" | "name") {
                    events.lock().unwrap().push(format!("get:{name}"));
                }
                if logging.load(Ordering::Relaxed)
                    && failure == Some(name)
                    && (name == "message" || selected_name.load(Ordering::Relaxed))
                {
                    return Err(AuthError::from_thrown(replacement.clone()));
                }
                fields.get(name)
            }
        },
    )
}

fn replacement() -> FieldValue {
    FieldMap::from([
        ("name".into(), "Error".into()),
        ("message".into(), "logger property failed".into()),
    ])
    .into()
}

fn prefix(has_name: bool) -> Vec<String> {
    let mut expected: Vec<String> = ["middleware", "has:name"].map(Into::into).into();
    if has_name {
        expected.push("get:name".into());
    }
    expected.extend(["get:message", "get:name"].map(Into::into));
    expected
}

fn logger_reads() -> Vec<String> {
    [
        "has:message",
        "get:message",
        "get:message",
        "get:message",
        "get:message",
        "get:message",
        "get:message",
        "get:name",
        "has:name",
    ]
    .map(Into::into)
    .into()
}

#[tokio::test]
async fn ordinary_error_names_keep_native_identity_and_live_property_order() -> AuthResult<()> {
    for name in [
        Some("RuntimeFailure".into()),
        Some(FieldMap::from([("kind".into(), "native-name".into())]).into()),
        None,
    ] {
        let events = Events::default();
        let cause = error_source(
            &events,
            name.clone(),
            "ordinary failure",
            None,
            &replacement(),
        );
        let harness = Harness::new(cause.clone(), &events, false, false);
        assert_empty_response(harness.run(true).await?)?;
        let logs = harness.logs.records.lock().unwrap();
        let [record] = logs.as_slice() else {
            panic!("The instance logger must receive one original error");
        };
        assert_eq!(record.level, LogLevel::Error);
        assert!(
            record
                .message
                .strict_equals(name.as_ref().unwrap_or(&"".into()))
        );
        let [argument] = record.arguments.as_slice() else {
            panic!("The instance logger must retain one original argument");
        };
        assert!(argument.strict_equals(&cause));
        let mut expected = prefix(name.is_some());
        expected.extend(logger_reads());
        if name.is_some() {
            expected.push("get:name".into());
        }
        expected.extend(["log", "get:name", "console"].map(Into::into));
        assert_eq!(*events.lock().unwrap(), expected);
        assert_eq!(harness.outer_count(), 1);
    }
    Ok(())
}

struct Callback {
    cause: FieldValue,
    events: Events,
}

impl ApiErrorHandler<S> for Callback {
    fn on_error(
        &self,
        error: &AuthError,
        _: &crate::AuthContext<S>,
    ) -> AuthResult<Option<ApiErrorTask>> {
        assert!(error.raw_value().unwrap().strict_equals(&self.cause));
        self.events.lock().unwrap().push("callback".into());
        Ok(None)
    }
}

#[tokio::test]
async fn disabled_callback_and_throw_keep_independent_outer_error_policy() -> AuthResult<()> {
    for policy in ["disabled", "callback", "throw"] {
        let events = Events::default();
        let cause = error_source(
            &events,
            Some("RuntimeFailure".into()),
            "ordinary failure",
            None,
            &replacement(),
        );
        let harness = Harness::new(
            cause.clone(),
            &events,
            policy == "disabled",
            policy == "throw",
        );
        if policy == "callback" {
            harness.context.extensions.insert(Arc::new(Callback {
                cause: cause.clone(),
                events: events.clone(),
            }) as Arc<dyn ApiErrorHandler<S>>);
        }
        let result = harness.run(true).await;
        if policy == "throw" {
            assert!(
                result
                    .unwrap_err()
                    .raw_value()
                    .unwrap()
                    .strict_equals(&cause)
            );
        } else {
            assert_empty_response(result?)?;
        }
        assert!(harness.logs.records.lock().unwrap().is_empty());
        let mut expected = prefix(true);
        if policy == "callback" {
            expected.push("callback".into());
        }
        expected.push("get:name".into());
        if policy != "throw" {
            expected.push("console".into());
        }
        assert_eq!(*events.lock().unwrap(), expected, "{policy}");
        assert_eq!(harness.outer_count(), usize::from(policy != "throw"));
    }
    Ok(())
}

#[tokio::test]
async fn logger_property_failures_escape_with_original_replacement_identity() {
    for failure in ["name", "message"] {
        let events = Events::default();
        let replacement = replacement();
        let cause = error_source(
            &events,
            Some("RuntimeFailure".into()),
            "ordinary failure",
            Some(failure),
            &replacement,
        );
        let harness = Harness::new(cause, &events, false, false);
        let error = harness.run(true).await.unwrap_err();
        assert!(error.raw_value().unwrap().strict_equals(&replacement));
        assert!(harness.logs.records.lock().unwrap().is_empty());
        assert_eq!(harness.outer_count(), 0);
        let mut expected = prefix(true);
        if failure == "message" {
            expected.extend(["has:message", "get:message"].map(Into::into));
        } else {
            expected.extend(logger_reads());
            expected.push("get:name".into());
        }
        assert_eq!(*events.lock().unwrap(), expected, "{failure}");
    }
}

#[tokio::test]
async fn database_diagnostics_reread_each_test_and_log_only_the_live_message() -> AuthResult<()> {
    for (keyword, message_reads) in [
        ("no column", 3),
        ("column", 4),
        ("relation", 5),
        ("table", 6),
        ("does not exist", 7),
    ] {
        let events = Events::default();
        let message = format!("diagnostic: {keyword}");
        let cause = error_source(
            &events,
            Some("RuntimeFailure".into()),
            &message,
            None,
            &replacement(),
        );
        let harness = Harness::new(cause, &events, false, false);
        assert_empty_response(harness.run(true).await?)?;
        let logs = harness.logs.records.lock().unwrap();
        let [record] = logs.as_slice() else {
            panic!("The instance logger must receive one database diagnostic");
        };
        assert_eq!(record.level, LogLevel::Error);
        assert_eq!(record.message, FieldValue::from(message));
        assert!(record.arguments.is_empty());
        let mut expected = prefix(true);
        expected.push("has:message".into());
        expected.extend(std::iter::repeat_n("get:message".into(), message_reads));
        expected.extend(["log", "get:name", "console"].map(Into::into));
        assert_eq!(*events.lock().unwrap(), expected, "{keyword}");
        assert_eq!(harness.outer_count(), 1);
    }
    Ok(())
}
