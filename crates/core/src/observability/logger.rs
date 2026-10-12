use std::{
    error::Error,
    fmt,
    sync::{Arc, LazyLock},
};

mod colors;

use serde_json::Value;

/// Ordering preserves the separate success threshold; success callbacks receive `Info`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord)]
pub enum LogLevel {
    Debug,
    Info,
    Success,
    #[default]
    Warn,
    Error,
}

impl LogLevel {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Debug => "debug",
            Self::Info => "info",
            Self::Success => "success",
            Self::Warn => "warn",
            Self::Error => "error",
        }
    }

    fn name(self) -> &'static str {
        match self {
            Self::Debug => "DEBUG",
            Self::Info => "INFO",
            Self::Success => "SUCCESS",
            Self::Warn => "WARN",
            Self::Error => "ERROR",
        }
    }

    fn color(self) -> &'static str {
        match self {
            Self::Debug => "\x1b[35m",
            Self::Info => "\x1b[34m",
            Self::Success => "\x1b[32m",
            Self::Warn => "\x1b[33m",
            Self::Error => "\x1b[31m",
        }
    }
}

/// Callback arguments remain separate from the message and retain structured values and errors.
#[derive(Clone, Copy, Debug)]
pub enum LogArgument<'a> {
    Text(&'a str),
    Value(&'a Value),
    /// Retain undefined, native values, and object identity until the sink chooses a projection.
    Native(&'a crate::FieldValue),
    /// Borrow the concrete error so callbacks can inspect its type without replacing the error.
    Error(&'a (dyn Error + Send + Sync + 'static)),
}

impl<'a> From<&'a str> for LogArgument<'a> {
    fn from(value: &'a str) -> Self {
        Self::Text(value)
    }
}

impl LogArgument<'_> {
    fn display_string(self) -> crate::AuthResult<String> {
        Ok(match self {
            Self::Text(value) => value.to_owned(),
            Self::Value(value) => {
                let native = crate::FieldValue::from(value.clone());
                String::from_utf16_lossy(native.display_utf16()?.as_utf16())
            }
            Self::Native(value) => String::from_utf16_lossy(value.display_utf16()?.as_utf16()),
            Self::Error(error) => error.to_string(),
        })
    }
}

impl fmt::Display for LogArgument<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.display_string().map_err(|_| fmt::Error)?)
    }
}

/// Synchronous application logger. The callback receives original values after message conversion.
pub trait LogSink: Send + Sync {
    fn log(&self, level: LogLevel, message: LogArgument<'_>, arguments: &[LogArgument<'_>]);
}

/// Per-auth logger policy. The default sink emits Rust tracing events.
#[derive(Clone, Default)]
pub struct LoggerConfig {
    /// Omission keeps logging enabled without reporting an explicit telemetry option.
    pub disabled: Option<bool>,
    /// Omission uses the warning threshold.
    pub level: Option<LogLevel>,
    /// Control the default message renderer. Custom sinks receive unformatted messages.
    pub disable_colors: Option<bool>,
    pub log: Option<Arc<dyn LogSink>>,
}

impl fmt::Debug for LoggerConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LoggerConfig")
            .field("disabled", &self.disabled)
            .field("level", &self.level)
            .field("disable_colors", &self.disable_colors)
            .field("custom_sink", &self.log.is_some())
            .finish()
    }
}

impl LoggerConfig {
    /// Freeze the environment-dependent renderer when creating an auth instance.
    pub(crate) fn resolved(&self) -> Self {
        let mut logger = self.clone();
        logger.disable_colors = Some(!self.colors_enabled());
        logger
    }

    fn colors_enabled(&self) -> bool {
        self.disable_colors.map_or_else(
            || colors::enabled(|name| std::env::var(name).ok()),
            |disabled| !disabled,
        )
    }

    pub fn enabled(&self, level: LogLevel) -> bool {
        !self.disabled.unwrap_or(false) && level >= self.level.unwrap_or_default()
    }

    /// Convert the message before selecting the sink. Preserve a native conversion failure.
    pub fn log<'a>(
        &self,
        level: LogLevel,
        message: impl Into<LogArgument<'a>>,
        arguments: &[LogArgument<'_>],
    ) -> crate::AuthResult<()> {
        let message = message.into();
        if !self.enabled(level) {
            return Ok(());
        }
        let prefix = self.prefix(level);
        let formatted = format!("{prefix}{}", message.display_string()?);
        self.emit(level, message, formatted, arguments);
        Ok(())
    }

    fn prefix(&self, level: LogLevel) -> String {
        let colors = self.colors_enabled();
        let time = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
        if colors {
            format!(
                "\x1b[2m{time}\x1b[0m {}{}\x1b[0m \x1b[1m[Better Auth]:\x1b[0m ",
                level.color(),
                level.name()
            )
        } else {
            format!("{time} {} [Better Auth]: ", level.name())
        }
    }

    fn emit(
        &self,
        level: LogLevel,
        original: LogArgument<'_>,
        message: String,
        arguments: &[LogArgument<'_>],
    ) {
        if let Some(sink) = &self.log {
            sink.log(
                if level == LogLevel::Success {
                    LogLevel::Info
                } else {
                    level
                },
                original,
                arguments,
            );
            return;
        }
        match level {
            LogLevel::Debug => tracing::debug!(target: "better-auth", message, ?arguments),
            LogLevel::Info | LogLevel::Success => {
                tracing::info!(target: "better-auth", message, ?arguments)
            }
            LogLevel::Warn => tracing::warn!(target: "better-auth", message, ?arguments),
            LogLevel::Error => tracing::error!(target: "better-auth", message, ?arguments),
        }
    }

    fn text(&self, level: LogLevel, message: &str, arguments: &[LogArgument<'_>]) {
        if self.enabled(level) {
            let formatted = format!("{}{message}", self.prefix(level));
            self.emit(level, message.into(), formatted, arguments);
        }
    }

    pub fn debug(&self, message: &str, arguments: &[LogArgument<'_>]) {
        self.text(LogLevel::Debug, message, arguments);
    }
    pub fn info(&self, message: &str, arguments: &[LogArgument<'_>]) {
        self.text(LogLevel::Info, message, arguments);
    }
    pub fn success(&self, message: &str, arguments: &[LogArgument<'_>]) {
        self.text(LogLevel::Success, message, arguments);
    }
    pub fn warn(&self, message: &str, arguments: &[LogArgument<'_>]) {
        self.text(LogLevel::Warn, message, arguments);
    }
    pub fn error(&self, message: &str, arguments: &[LogArgument<'_>]) {
        self.text(LogLevel::Error, message, arguments);
    }
}

/// Use the nearest endpoint or native helper logger. HTTP policy resolution preserves the caller's logger.
pub fn current() -> LoggerConfig {
    crate::request_runtime::current_logger().unwrap_or_else(|| default_logger().clone())
}

pub(crate) fn default_logger() -> &'static LoggerConfig {
    static LOGGER: LazyLock<LoggerConfig> = LazyLock::new(|| LoggerConfig::default().resolved());
    &LOGGER
}

#[cfg(test)]
#[expect(
    clippy::expect_used,
    clippy::panic_in_result_fn,
    reason = "Logger contracts assert callback values and must fail if the recording mutex is poisoned."
)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    #[derive(Default)]
    struct Capture(Mutex<Vec<(LogLevel, String, Vec<Value>)>>);
    impl LogSink for Capture {
        fn log(&self, level: LogLevel, message: LogArgument<'_>, arguments: &[LogArgument<'_>]) {
            let arguments = arguments
                .iter()
                .map(|value| match value {
                    LogArgument::Text(value) => Value::String((*value).into()),
                    LogArgument::Value(value) => (*value).clone(),
                    LogArgument::Native(value) => value
                        .json()
                        .expect("contract logger argument must serialize")
                        .expect("contract logger argument must be JSON-defined"),
                    LogArgument::Error(error) => Value::String(error.to_string()),
                })
                .collect();
            self.0.lock().expect("capture mutex is not poisoned").push((
                level,
                message.to_string(),
                arguments,
            ));
        }
    }

    #[tokio::test]
    async fn instance_snapshot_survives_option_replacement_and_reinitializes_for_new_auth()
    -> crate::AuthResult<()> {
        struct ReplaceOptions(crate::AuthConfig);
        #[async_trait::async_trait]
        impl crate::AuthPlugin<crate::store::StatelessSchema> for ReplaceOptions {
            fn name(&self) -> &'static str {
                "replace-logger-options"
            }
            fn routes(&self) -> Vec<crate::AuthRoute> {
                Vec::new()
            }
            async fn on_init(
                &self,
                context: &mut crate::AuthInitContext<crate::store::StatelessSchema>,
            ) -> crate::AuthResult<()> {
                context.config = Arc::new(self.0.clone());
                context.logger().error("during initialization", &[]);
                Ok(())
            }
        }

        for disable_colors in [None, Some(true), Some(false)] {
            let original = Arc::new(Capture::default());
            let replacement = Arc::new(Capture::default());
            let mut options = crate::AuthConfig::default();
            options.logger.disable_colors = disable_colors;
            options.logger.log = Some(original.clone());
            options.initialize_logger();
            let snapshot = options.logger().disable_colors;
            assert!(snapshot.is_some());
            assert_eq!(options.logger.disable_colors, disable_colors);
            let mut next_options = options.clone();
            next_options.logger.disable_colors = snapshot.map(|value| !value);
            next_options.logger.log = Some(replacement.clone());
            let database = Arc::new(crate::store::EphemeralStore::default());
            let mut init = crate::AuthInitContext::new(Arc::new(options), database.clone());
            init.initialize_plugin(&ReplaceOptions(next_options))
                .await?;
            assert_eq!(init.logger().disable_colors, snapshot);
            assert_eq!(init.config.logger().disable_colors, snapshot);
            assert_eq!(
                init.config.logger.disable_colors,
                snapshot.map(|value| !value)
            );
            let context = crate::AuthContext::new(init.config.clone(), database);
            let derived = context.clone();
            derived.logger().error("after initialization", &[]);
            assert_eq!(derived.logger().disable_colors, snapshot);
            assert_eq!(
                original
                    .0
                    .lock()
                    .expect("capture mutex is not poisoned")
                    .as_slice(),
                [
                    (
                        LogLevel::Error,
                        "during initialization".to_owned(),
                        Vec::new()
                    ),
                    (
                        LogLevel::Error,
                        "after initialization".to_owned(),
                        Vec::new()
                    ),
                ]
            );
            assert!(
                replacement
                    .0
                    .lock()
                    .expect("capture mutex is not poisoned")
                    .is_empty()
            );
            let mut reused_options = (*init.config).clone();
            reused_options.initialize_logger();
            assert_eq!(
                reused_options.logger().disable_colors,
                snapshot.map(|value| !value)
            );
            reused_options.logger().error("new instance", &[]);
            assert_eq!(
                replacement
                    .0
                    .lock()
                    .expect("capture mutex is not poisoned")
                    .as_slice(),
                [(LogLevel::Error, "new instance".to_owned(), Vec::new())]
            );
        }
        Ok(())
    }

    #[test]
    fn thresholds_keep_success_order_and_custom_arguments_unformatted() -> crate::AuthResult<()> {
        let levels = [
            LogLevel::Debug,
            LogLevel::Info,
            LogLevel::Success,
            LogLevel::Warn,
            LogLevel::Error,
        ];
        let structured = serde_json::json!({"value": 1});
        let tail = Value::String("tail".into());
        for configured_level in [None].into_iter().chain(levels.map(Some)) {
            let level = configured_level.unwrap_or_default();
            for disabled in [None, Some(false), Some(true)] {
                let sink = Arc::new(Capture::default());
                let logger = LoggerConfig {
                    level: configured_level,
                    disabled,
                    log: Some(sink.clone()),
                    disable_colors: Some(false),
                };
                for event in levels {
                    logger.log(
                        event,
                        "literal %s",
                        &[LogArgument::Value(&structured), LogArgument::Value(&tail)],
                    )?;
                }
                let expected: Vec<_> = levels
                    .into_iter()
                    .filter(|event| !disabled.unwrap_or(false) && *event >= level)
                    .map(|event| {
                        (
                            if event == LogLevel::Success {
                                LogLevel::Info
                            } else {
                                event
                            },
                            "literal %s".to_owned(),
                            vec![structured.clone(), tail.clone()],
                        )
                    })
                    .collect();
                assert_eq!(
                    *sink.0.lock().expect("capture mutex is not poisoned"),
                    expected
                );
            }
        }
        Ok(())
    }

    #[test]
    fn native_arguments_reach_custom_sink_without_coercion_or_identity_loss()
    -> crate::AuthResult<()> {
        #[derive(Default)]
        struct NativeCapture(Mutex<Option<crate::FieldValue>>);
        impl LogSink for NativeCapture {
            fn log(&self, _: LogLevel, message: LogArgument<'_>, arguments: &[LogArgument<'_>]) {
                let (LogArgument::Text("native fields"), [LogArgument::Native(argument)]) =
                    (message, arguments)
                else {
                    panic!("native arguments must retain their representation");
                };
                *self.0.lock().expect("capture mutex is not poisoned") = Some((*argument).clone());
            }
        }
        let message: crate::FieldValue = crate::Utf16String::from_units(vec![0xd800]).into();
        let argument: crate::FieldValue = crate::FieldMap::from([
            ("missing".into(), crate::FieldValue::Undefined),
            ("message".into(), message.clone()),
        ])
        .into();
        let sink = Arc::new(NativeCapture::default());
        let logger = LoggerConfig {
            log: Some(sink.clone()),
            ..Default::default()
        };
        logger.log(
            LogLevel::Error,
            "native fields",
            &[LogArgument::Native(&argument)],
        )?;
        let observed = sink.0.lock().expect("capture mutex is not poisoned");
        let observed_argument = observed.as_ref().expect("logger was called");
        assert!(observed_argument.strict_equals(&argument));
        assert!(
            observed_argument
                .model_property("message")
                .expect("native object is readable")
                .strict_equals(&message)
        );
        assert!(
            observed_argument
                .model_property("missing")
                .expect("native object is readable")
                .is_undefined()
        );
        assert_eq!(LogArgument::Native(&message).to_string(), "\u{fffd}");
        LoggerConfig::default().log(LogLevel::Error, LogArgument::Native(&message), &[])?;
        Ok(())
    }
}
