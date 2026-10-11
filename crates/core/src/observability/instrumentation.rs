use std::future::Future;

use tracing::{Instrument, Span, field};

use crate::AuthResult;

#[derive(Clone, Debug, Default)]
pub struct ExperimentalConfig {
    pub instrumentation: InstrumentationConfig,
}

/// Control Better Auth spans independently of logging and usage reporting.
#[derive(Clone, Debug)]
pub struct InstrumentationConfig {
    pub enabled: bool,
}

impl Default for InstrumentationConfig {
    fn default() -> Self {
        Self { enabled: true }
    }
}

/// Semantic fields emitted at endpoint, hook and adapter boundaries.
#[derive(Clone, Copy, Default)]
pub struct SpanAttributes<'a> {
    pub route: Option<&'a str>,
    pub operation_id: Option<&'a str>,
    pub hook_type: Option<&'a str>,
    pub context: Option<&'a str>,
    pub collection: Option<&'a str>,
    pub database_operation: Option<&'a str>,
}

fn span(config: &InstrumentationConfig, name: &str, attributes: SpanAttributes<'_>) -> Span {
    if !config.enabled {
        return Span::none();
    }
    let span = tracing::info_span!(target: "better-auth", "better_auth",
        "otel.name" = name,
        "otel.scope.name" = "better-auth", "otel.scope.version" = "1.7.6",
        "http.route" = field::Empty, "better_auth.operation_id" = field::Empty,
        "better_auth.hook.type" = field::Empty, "better_auth.context" = field::Empty,
        "db.collection.name" = field::Empty, "db.operation.name" = field::Empty,
        "http.response.status_code" = field::Empty,
        "otel.status_code" = field::Empty, "otel.status_description" = field::Empty,
    );
    for (name, value) in [
        ("http.route", attributes.route),
        ("better_auth.operation_id", attributes.operation_id),
        ("better_auth.hook.type", attributes.hook_type),
        ("better_auth.context", attributes.context),
        ("db.collection.name", attributes.collection),
        ("db.operation.name", attributes.database_operation),
    ] {
        if let Some(value) = value {
            let _ = span.record(name, value);
        }
    }
    span
}

/// Trace one actual operation. Dropping the future also releases its span.
pub fn with_span<T, F>(
    config: &InstrumentationConfig,
    name: &str,
    attributes: SpanAttributes<'_>,
    operation: F,
) -> impl Future<Output = AuthResult<T>> + use<T, F>
where
    F: Future<Output = AuthResult<T>>,
{
    // Box the operation before constructing the instrumented future; nested dispatchers can be large.
    let operation = Box::pin(operation);
    let enabled = config.enabled;
    let span = span(config, name, attributes);
    let records = span.clone();
    async move {
        let result = operation.await;
        if enabled && let Err(error) = &result {
            let redirect = if let Some(value) = error.raw_value() {
                if let Some(object) = value.as_object()
                    && object.has_property("name")?
                    && object.get("name")?.is_some_and(|name| name.strict_equals(&"APIError".into()))
                    && object.has_property("statusCode")?
                {
                    let status = object.get("statusCode")?.unwrap_or_default();
                    crate::query::field_number(&status)? >= 300.0
                        && crate::query::field_number(&status)? < 400.0
                } else {
                    false
                }
            } else {
                error.is_api_error()? && {
                    let status = error.status_code()?.field_value();
                    crate::query::field_number(&status)? >= 300.0
                        && crate::query::field_number(&status)? < 400.0
                }
            };
            if redirect {
                let status = error.status_code()?.into_field_value();
                match status {
                    crate::FieldValue::Number(status) => { let _ = records.record("http.response.status_code", status); }
                    status => { let _ = records.record("http.response.status_code", field::debug(status)); }
                }
                let _ = records.record("otel.status_code", "OK");
            } else {
                // Record the exception before reading its dynamic message, as the upstream tracer does.
                let diagnostic = if error.raw_value().is_some() {
                    error.to_string()
                } else {
                    error.instrumentation_message()?
                };
                tracing::event!(name: "exception", target: "better-auth", tracing::Level::ERROR, "exception.message" = %diagnostic);
                let message = error.instrumentation_message()?;
                let _ = records.record("otel.status_code", "ERROR");
                let _ = records.record("otel.status_description", message.as_str());
            }
        }
        result
    }.instrument(span)
}

/// Trace an actual matched endpoint hook; matcher evaluation stays outside this boundary.
pub async fn with_endpoint_hook<T>(
    config: &crate::AuthConfig,
    request: &crate::AuthRequest,
    phase: &str,
    source: &str,
    operation: impl Future<Output = AuthResult<T>>,
) -> AuthResult<T> {
    let context = crate::hooks::current_request_hook_context();
    let route = if request.is_server_only() {
        "/:virtual"
    } else {
        context.as_ref().map_or(request.path(), |context| {
            context.path.as_deref().unwrap_or("/:virtual")
        })
    };
    let operation_id = context
        .as_ref()
        .and_then(|context| context.operation_id.as_deref())
        .unwrap_or(route);
    with_span(
        &config.experimental.instrumentation,
        &format!("hook {phase} {route} {source}"),
        SpanAttributes {
            route: Some(route),
            operation_id: Some(operation_id),
            hook_type: Some(phase),
            context: Some(source),
            ..Default::default()
        },
        async {
            match operation.await {
                Ok(value) => Ok(value),
                Err(error) => {
                    request.mark_hook_error_handled();
                    Err(crate::endpoint_dispatch::endpoint_error(error, request)?)
                }
            }
        },
    )
    .await
}
