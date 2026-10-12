use std::{
    error::Error,
    fmt,
    sync::{Arc, LazyLock},
};

mod colors;
mod options;

pub use options::{LoggerConfig, LoggerOptions, LoggerSource};

use crate::{AuthError, AuthResult, FieldObject, FieldValue};
use serde_json::Value;

/// Ordering preserves the separate success threshold; success callbacks receive Info.
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
    /// Return the upstream level name.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Debug => "debug",
            Self::Info => "info",
            Self::Success => "success",
            Self::Warn => "warn",
            Self::Error => "error",
        }
    }

    fn index(self) -> i8 {
        match self {
            Self::Debug => 0,
            Self::Info => 1,
            Self::Success => 2,
            Self::Warn => 3,
            Self::Error => 4,
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
    Native(&'a FieldValue),
    /// Borrow the concrete error so callbacks can inspect its type without replacing the error.
    Error(&'a (dyn Error + Send + Sync + 'static)),
}

impl<'a> From<&'a str> for LogArgument<'a> {
    fn from(value: &'a str) -> Self {
        Self::Text(value)
    }
}

impl LogArgument<'_> {
    fn display_string(self) -> AuthResult<String> {
        Ok(match self {
            Self::Text(value) => value.to_owned(),
            Self::Value(value) => {
                let native = FieldValue::from(value.clone());
                String::from_utf16_lossy(native.display_utf16()?.as_utf16())
            }
            Self::Native(value) => String::from_utf16_lossy(value.display_utf16()?.as_utf16()),
            Self::Error(error) => match error
                .downcast_ref::<AuthError>()
                .and_then(AuthError::raw_value)
            {
                Some(value) => Self::Native(value).display_string()?,
                None => error.to_string(),
            },
        })
    }

    fn native_value(self) -> AuthResult<FieldValue> {
        match self {
            Self::Text(value) => Ok(value.into()),
            Self::Value(value) => Ok(value.clone().into()),
            Self::Native(value) => Ok(value.clone()),
            Self::Error(error) => match error.downcast_ref::<AuthError>() {
                Some(error) => error.callback_value(),
                None => AuthError::internal(error.to_string()).callback_value(),
            },
        }
    }
}

impl fmt::Display for LogArgument<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.display_string().map_err(|_| fmt::Error)?)
    }
}

/// Synchronous application logger. Failures retain the original error and stop the caller.
pub trait LogSink: Send + Sync {
    fn log(
        &self,
        level: LogLevel,
        message: LogArgument<'_>,
        arguments: &[LogArgument<'_>],
    ) -> AuthResult<()>;
}

/// An instance logger with frozen policy and a retained, live callback owner.
#[derive(Clone)]
pub struct Logger(Arc<BoundLogger>);

struct BoundLogger {
    policy: LoggerPolicy,
    owner: LoggerOwner,
}

struct LoggerPolicy {
    enabled: bool,
    level: FieldValue,
    threshold: i8,
    colors_enabled: bool,
}

enum LoggerOwner {
    Typed(LoggerOptions),
    Native(FieldObject),
}

impl fmt::Debug for Logger {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Logger")
            .field("enabled", &self.0.policy.enabled)
            .field("level", &self.0.policy.level)
            .field("colors_enabled", &self.0.policy.colors_enabled)
            .finish_non_exhaustive()
    }
}

impl LoggerPolicy {
    fn new(enabled: bool, level: FieldValue, colors_enabled: bool) -> Self {
        let threshold = [
            LogLevel::Debug,
            LogLevel::Info,
            LogLevel::Success,
            LogLevel::Warn,
            LogLevel::Error,
        ]
        .into_iter()
        .find(|candidate| level.strict_equals(&candidate.as_str().into()))
        .map_or(-1, LogLevel::index);
        Self {
            enabled,
            level,
            threshold,
            colors_enabled,
        }
    }

    fn typed(options: &LoggerConfig) -> Self {
        Self::new(
            options.disabled != Some(true),
            options.level.unwrap_or_default().as_str().into(),
            options
                .disable_colors
                .map_or_else(environment_colors, |disabled| !disabled),
        )
    }
}

fn environment_colors() -> bool {
    colors::enabled(|name| std::env::var(name).ok())
}

impl Logger {
    /// Bind the current policy once and retain the selected owner for callback lookup.
    pub fn new(source: impl Into<LoggerSource>) -> AuthResult<Self> {
        let source = source.into();
        match source {
            LoggerSource::Config(options) => Ok(Self::typed(LoggerOptions::new(options))),
            LoggerSource::Live(options) => Ok(Self::typed(options)),
            LoggerSource::Native(ref owner) => {
                let enabled = !source.raw_disabled()?.strict_equals(&true.into());
                let mut level = source.raw_level()?;
                if level.is_null() || level.is_undefined() {
                    level = LogLevel::Warn.as_str().into();
                }
                // Upstream checks presence before reading the color value again.
                let colors_enabled = if source.raw_disable_colors()?.is_undefined() {
                    environment_colors()
                } else {
                    !source.raw_disable_colors()?.is_truthy()
                };
                Ok(Self(Arc::new(BoundLogger {
                    policy: LoggerPolicy::new(enabled, level, colors_enabled),
                    owner: LoggerOwner::Native(owner.clone()),
                })))
            }
        }
    }

    fn typed(options: LoggerOptions) -> Self {
        let policy = LoggerPolicy::typed(&options.snapshot());
        Self(Arc::new(BoundLogger {
            policy,
            owner: LoggerOwner::Typed(options),
        }))
    }

    /// Borrow the original resolved level, including an unrecognized native value.
    pub fn level(&self) -> &FieldValue {
        &self.0.policy.level
    }

    /// Apply the instance's frozen enabled flag and level threshold.
    pub fn enabled(&self, level: LogLevel) -> bool {
        self.0.policy.enabled && self.publishes(level)
    }

    /// Compare the frozen threshold without applying the logging enabled flag.
    pub(crate) fn publishes(&self, level: LogLevel) -> bool {
        level.index() >= self.0.policy.threshold
    }

    /// Format the message before reading the current callback from the original owner.
    pub fn log<'a>(
        &self,
        level: LogLevel,
        message: impl Into<LogArgument<'a>>,
        arguments: &[LogArgument<'_>],
    ) -> AuthResult<()> {
        let message = message.into();
        if !self.enabled(level) {
            return Ok(());
        }
        let formatted = format!("{}{}", self.prefix(level), message.display_string()?);
        self.emit(level, message, formatted, arguments)
    }

    fn prefix(&self, level: LogLevel) -> String {
        let time = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
        if self.0.policy.colors_enabled {
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
    ) -> AuthResult<()> {
        let callback_level = if level == LogLevel::Success {
            LogLevel::Info
        } else {
            level
        };
        match &self.0.owner {
            LoggerOwner::Typed(options) => {
                if let Some(sink) = options.sink() {
                    return sink.log(callback_level, original, arguments);
                }
            }
            LoggerOwner::Native(owner) => {
                if matches!(owner.get("log")?, Some(FieldValue::Function(_))) {
                    // The second property read belongs to the method call, not the callable check.
                    let callback = owner.get("log")?.unwrap_or_default();
                    let mut values = Vec::with_capacity(arguments.len() + 2);
                    values.push(callback_level.as_str().into());
                    values.push(original.native_value()?);
                    for argument in arguments {
                        values.push(argument.native_value()?);
                    }
                    let FieldValue::Function(callback) = callback else {
                        return Err(AuthError::type_error("options.log is not a function"));
                    };
                    let _ = callback.call_with(&owner.clone().into(), &values)?;
                    return Ok(());
                }
            }
        }
        match level {
            LogLevel::Debug => tracing::debug!(target: "better-auth", message, ?arguments),
            LogLevel::Info | LogLevel::Success => {
                tracing::info!(target: "better-auth", message, ?arguments)
            }
            LogLevel::Warn => tracing::warn!(target: "better-auth", message, ?arguments),
            LogLevel::Error => tracing::error!(target: "better-auth", message, ?arguments),
        }
        Ok(())
    }

    /// Emit a debug message through the instance logger.
    pub fn debug(&self, message: &str, arguments: &[LogArgument<'_>]) -> AuthResult<()> {
        self.log(LogLevel::Debug, message, arguments)
    }

    /// Emit an informational message through the instance logger.
    pub fn info(&self, message: &str, arguments: &[LogArgument<'_>]) -> AuthResult<()> {
        self.log(LogLevel::Info, message, arguments)
    }

    /// Emit a success message with the separate success threshold.
    pub fn success(&self, message: &str, arguments: &[LogArgument<'_>]) -> AuthResult<()> {
        self.log(LogLevel::Success, message, arguments)
    }

    /// Emit a warning through the instance logger.
    pub fn warn(&self, message: &str, arguments: &[LogArgument<'_>]) -> AuthResult<()> {
        self.log(LogLevel::Warn, message, arguments)
    }

    /// Emit an error message through the instance logger.
    pub fn error(&self, message: &str, arguments: &[LogArgument<'_>]) -> AuthResult<()> {
        self.log(LogLevel::Error, message, arguments)
    }
}

/// Use the nearest endpoint or native helper logger without rebinding its options.
pub fn current() -> Logger {
    crate::request_runtime::current_logger().unwrap_or_else(|| default_logger().clone())
}

pub(crate) fn default_logger() -> &'static Logger {
    static LOGGER: LazyLock<Logger> =
        LazyLock::new(|| Logger::typed(LoggerOptions::new(LoggerConfig::default())));
    &LOGGER
}

/// Consume a terminal runtime failure without invoking the application logger or native getters.
#[doc(hidden)]
pub fn report_terminal_error(boundary: &'static str, error: AuthError) {
    tracing::error!(target: "better-auth::runtime", boundary, error = %error, "Authentication runtime failed");
}

#[cfg(test)]
#[expect(
    clippy::expect_used,
    clippy::panic_in_result_fn,
    reason = "Logger contracts inspect callback values and must fail on violated fixture invariants."
)]
mod tests;
