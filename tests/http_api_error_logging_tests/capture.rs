use super::*;
use tracing::{
    Event as TraceEvent, Metadata, Subscriber,
    field::{Field, Visit},
    span::{Attributes, Id, Record},
};

pub(super) struct Instance {
    pub(super) name: &'static str,
    pub(super) observations: Arc<Observations>,
}

fn native(value: LogArgument<'_>) -> FieldValue {
    match value {
        LogArgument::Text(value) => value.into(),
        LogArgument::Value(value) => value.clone().into(),
        LogArgument::Native(value) => value.clone(),
        LogArgument::Error(error) => error.to_string().into(),
    }
}

impl LogSink for Instance {
    #[expect(
        clippy::expect_used,
        reason = "The synchronous logger sink cannot propagate a capture failure"
    )]
    fn log(&self, level: LogLevel, message: LogArgument<'_>, arguments: &[LogArgument<'_>]) {
        lock(&self.observations.events)
            .expect("Logger observation lock must remain available")
            .push(Event::Log {
                sink: self.name,
                scope: self.observations.owner(),
                level,
                message: native(message),
                arguments: arguments.iter().copied().map(native).collect(),
            });
    }
}

#[derive(Default)]
struct Fields(Vec<(String, String)>);

impl Visit for Fields {
    fn record_str(&mut self, field: &Field, value: &str) {
        self.0.push((field.name().into(), value.into()));
    }

    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        self.0.push((field.name().into(), format!("{value:?}")));
    }
}

pub(super) struct DefaultLogger(pub(super) Arc<Observations>);

impl Subscriber for DefaultLogger {
    fn enabled(&self, metadata: &Metadata<'_>) -> bool {
        metadata.target() == "better-auth"
    }

    fn new_span(&self, _: &Attributes<'_>) -> Id {
        Id::from_u64(1)
    }

    fn record(&self, _: &Id, _: &Record<'_>) {}
    fn record_follows_from(&self, _: &Id, _: &Id) {}
    fn enter(&self, _: &Id) {}
    fn exit(&self, _: &Id) {}

    #[expect(
        clippy::expect_used,
        reason = "Tracing subscribers cannot propagate a capture failure"
    )]
    fn event(&self, event: &TraceEvent<'_>) {
        if event.metadata().name() == "exception" {
            return;
        }
        assert_eq!(event.metadata().level(), &tracing::Level::ERROR);
        let mut fields = Fields::default();
        event.record(&mut fields);
        lock(&self.0.events)
            .expect("Default logger observation lock must remain available")
            .push(Event::Default {
                scope: self.0.owner(),
                fields: fields.0,
            });
    }
}

#[expect(
    clippy::panic_in_result_fn,
    reason = "The contract must reject any changed renderer field, timestamp, or argument"
)]
pub(super) fn default_event(
    events: &[Event],
    before: chrono::DateTime<chrono::Utc>,
    after: chrono::DateTime<chrono::Utc>,
) -> AuthResult<Event> {
    let event = events
        .iter()
        .find(|event| matches!(event, Event::Default { .. }))
        .ok_or_else(|| AuthError::internal("The default logger must emit the API error message"))?;
    let Event::Default { scope, fields } = event else {
        return Err(AuthError::internal("Expected default logger event"));
    };
    let [(name, message), arguments] = fields.as_slice() else {
        return Err(AuthError::internal(
            "Default logger must retain message and arguments",
        ));
    };
    assert_eq!(name, "message");
    assert_eq!(arguments, &("arguments".into(), "[]".into()));
    assert_eq!(*scope, "none");
    let colors = match std::env::var_os("BETTER_AUTH_LOGGER_UPSTREAM_OBSERVATION") {
        Some(path) => {
            let observation: serde_json::Value = serde_json::from_slice(
                &std::fs::read(path).map_err(|error| AuthError::internal(error.to_string()))?,
            )
            .map_err(|error| AuthError::internal(error.to_string()))?;
            observation
                .get("colors")
                .and_then(Value::as_bool)
                .ok_or_else(|| {
                    AuthError::internal(
                        "Upstream logger observation must contain a boolean colors value",
                    )
                })?
        }
        None if std::env::var_os("GITHUB_ACTIONS").is_some() => {
            return Err(AuthError::internal(
                "CI must supply the upstream logger observation",
            ));
        }
        None => {
            eprintln!(
                "Upstream logger environment pairing is not configured; checking renderer shape only"
            );
            message.starts_with("\x1b[2m")
        }
    };
    let start = if colors { "\x1b[2m".len() } else { 0 };
    let timestamp = message.get(start..start + 24).ok_or_else(|| {
        AuthError::internal("Default logger must include an ISO millisecond timestamp")
    })?;
    let parsed = chrono::DateTime::parse_from_rfc3339(timestamp)
        .map_err(|error| AuthError::internal(error.to_string()))?
        .with_timezone(&chrono::Utc);
    assert_eq!(
        timestamp,
        parsed.to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
    );
    assert!(parsed.timestamp_millis() >= before.timestamp_millis());
    assert!(parsed.timestamp_millis() <= after.timestamp_millis());
    let expected = if colors {
        format!(
            "\x1b[2m{timestamp}\x1b[0m \x1b[31mERROR\x1b[0m \x1b[1m[Better Auth]:\x1b[0m {MESSAGE}"
        )
    } else {
        format!("{timestamp} ERROR [Better Auth]: {MESSAGE}")
    };
    assert_eq!(message, &expected);
    Ok(Event::Default {
        scope: "none",
        fields: vec![
            ("message".into(), expected),
            ("arguments".into(), "[]".into()),
        ],
    })
}
