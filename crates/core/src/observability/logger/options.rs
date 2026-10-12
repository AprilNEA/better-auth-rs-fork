use std::{fmt, sync::Arc};

use parking_lot::RwLock;

use super::{LogLevel, LogSink};
use crate::{AuthResult, FieldMap, FieldObject, FieldValue};

/// Authored logger options. Binding copies this value into a new runtime owner.
#[derive(Clone, Default)]
pub struct LoggerConfig {
    /// Omission keeps logging enabled without reporting an explicit telemetry option.
    pub disabled: Option<bool>,
    /// Omission uses the warning threshold.
    pub level: Option<LogLevel>,
    /// Control the default renderer. Custom sinks receive unformatted messages.
    pub disable_colors: Option<bool>,
    /// Receive the original message and borrowed arguments after message formatting.
    pub log: Option<Arc<dyn LogSink>>,
}

impl fmt::Debug for LoggerConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LoggerConfig")
            .field("disabled", &self.disabled)
            .field("level", &self.level)
            .field("disable_colors", &self.disable_colors)
            .field("custom_sink", &self.log.is_some())
            .finish()
    }
}

/// Shared typed options. Clones retain the owner observed by an existing logger.
#[derive(Clone, Debug, Default)]
pub struct LoggerOptions(Arc<RwLock<LoggerConfig>>);

impl LoggerOptions {
    /// Create a new owner from authored options.
    pub fn new(config: LoggerConfig) -> Self {
        Self(Arc::new(RwLock::new(config)))
    }

    /// Copy current authored options without changing the retained owner.
    pub fn snapshot(&self) -> LoggerConfig {
        self.0.read().clone()
    }

    /// Replace properties of the retained owner and return the previous options.
    pub fn replace(&self, config: LoggerConfig) -> LoggerConfig {
        std::mem::replace(&mut self.0.write(), config)
    }

    /// Replace or remove the callback observed by every logger bound to this owner.
    pub fn set_log(&self, sink: Option<Arc<dyn LogSink>>) {
        let previous = std::mem::replace(&mut self.0.write().log, sink);
        // A sink destructor may reenter the options; release the write guard before dropping it.
        drop(previous);
    }

    pub(super) fn sink(&self) -> Option<Arc<dyn LogSink>> {
        self.0.read().log.clone()
    }
}

/// Select exactly one authored, shared typed, or native logger-options source.
#[derive(Clone, Debug)]
pub enum LoggerSource {
    /// Copy authored options into a fresh owner when binding an instance.
    Config(LoggerConfig),
    /// Retain an existing shared typed owner.
    Live(LoggerOptions),
    /// Retain the original native object, including its getters and callback receiver.
    Native(FieldObject),
}

impl Default for LoggerSource {
    fn default() -> Self {
        Self::Config(LoggerConfig::default())
    }
}

impl From<LoggerConfig> for LoggerSource {
    fn from(value: LoggerConfig) -> Self {
        Self::Config(value)
    }
}

impl From<LoggerOptions> for LoggerSource {
    fn from(value: LoggerOptions) -> Self {
        Self::Live(value)
    }
}

impl From<FieldObject> for LoggerSource {
    fn from(value: FieldObject) -> Self {
        Self::Native(value)
    }
}

enum ScalarOption {
    Disabled,
    Level,
    DisableColors,
}

impl ScalarOption {
    fn name(&self) -> &'static str {
        match self {
            Self::Disabled => "disabled",
            Self::Level => "level",
            Self::DisableColors => "disableColors",
        }
    }

    fn typed(&self, config: &LoggerConfig) -> FieldValue {
        match self {
            Self::Disabled => config.disabled.map_or(FieldValue::Undefined, Into::into),
            Self::Level => config
                .level
                .map_or(FieldValue::Undefined, |level| level.as_str().into()),
            Self::DisableColors => config
                .disable_colors
                .map_or(FieldValue::Undefined, Into::into),
        }
    }
}

impl LoggerSource {
    fn scalar(&self, option: ScalarOption) -> AuthResult<FieldValue> {
        Ok(match self {
            Self::Config(config) => option.typed(config),
            Self::Live(options) => option.typed(&options.0.read()),
            Self::Native(object) => object.get(option.name())?.unwrap_or_default(),
        })
    }

    pub(crate) fn raw_disabled(&self) -> AuthResult<FieldValue> {
        self.scalar(ScalarOption::Disabled)
    }

    pub(crate) fn raw_level(&self) -> AuthResult<FieldValue> {
        self.scalar(ScalarOption::Level)
    }

    pub(crate) fn raw_disable_colors(&self) -> AuthResult<FieldValue> {
        self.scalar(ScalarOption::DisableColors)
    }

    pub(crate) fn log_is_truthy(&self) -> AuthResult<bool> {
        Ok(match self {
            Self::Config(config) => config.log.is_some(),
            Self::Live(options) => options.0.read().log.is_some(),
            Self::Native(object) => object.get("log")?.is_some_and(|value| value.is_truthy()),
        })
    }

    /// Read current raw options in upstream telemetry order without applying runtime defaults.
    #[doc(hidden)]
    pub fn telemetry_options(&self) -> AuthResult<FieldMap> {
        let disabled = self.raw_disabled()?;
        let level = self.raw_level()?;
        let log = self.log_is_truthy()?;
        Ok(FieldMap::from([
            ("disabled".into(), disabled),
            ("level".into(), level),
            ("log".into(), log.into()),
        ]))
    }
}

#[cfg(test)]
#[expect(
    clippy::expect_used,
    reason = "The callback contract requires the retained options owner to remain available."
)]
mod tests;
