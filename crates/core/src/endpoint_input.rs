//! Endpoint input projection, separate from the original transport request.

use crate::{AuthRequest, AuthResult, FieldValue, RuntimeExtensions};
use serde_json::Value;

mod validator;
pub use validator::{BodyValidator, InputValidator, QueryValidator};
mod request_cache;
pub(crate) use request_cache::{RequestBodyCache, RequestQueryCache};

#[cfg(test)]
mod dispatch_tests;
#[cfg(test)]
mod tests;

/// One schema result, retaining its typed input and exact callback projection.
#[derive(Clone)]
pub struct ValidatedInput {
    projection: FieldValue,
    typed: RuntimeExtensions,
}

/// The body schema result. Query schemas use the same native input representation.
pub type ValidatedBody = ValidatedInput;

impl std::fmt::Debug for ValidatedInput {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ValidatedInput")
            .finish_non_exhaustive()
    }
}

impl ValidatedInput {
    /// Retain a JSON schema result and its typed value.
    pub fn new<T: Send + Sync + 'static>(projection: Option<Value>, value: T) -> Self {
        Self::native(projection.map(FieldValue::from).unwrap_or_default(), value)
    }

    /// Retain a native schema result without reading properties or converting values.
    pub fn native<T: Send + Sync + 'static>(projection: FieldValue, value: T) -> Self {
        let mut typed = RuntimeExtensions::default();
        typed.insert(value);
        Self { projection, typed }
    }

    /// Read the typed result without parsing the validated projection again.
    pub fn get<T: Send + Sync + 'static>(&self) -> Option<&T> {
        self.typed.get()
    }

    /// Share the validated projection without reading properties or serializing native values.
    pub fn field_value(&self) -> FieldValue {
        self.projection.clone()
    }

    /// Preserve JSON input for endpoints without a schema.
    pub fn unvalidated(projection: Option<Value>) -> Self {
        Self::unvalidated_native(projection.map(FieldValue::from).unwrap_or_default())
    }

    /// Preserve native input for endpoints without a schema.
    pub fn unvalidated_native(value: FieldValue) -> Self {
        Self {
            projection: value,
            typed: RuntimeExtensions::default(),
        }
    }
}

/// Validate a record body while retaining values and removing the prototype setter key.
pub fn record_body(request: &AuthRequest) -> AuthResult<ValidatedBody> {
    let body = parse_record_body(request)?;
    Ok(ValidatedBody::new(Some(Value::Object(body.clone())), body))
}

/// Read a validated record, including calls that invoke a plugin directly.
pub fn record_input(request: &AuthRequest) -> AuthResult<serde_json::Map<String, Value>> {
    request
        .validated_body::<serde_json::Map<String, Value>>()
        .cloned()
        .map_or_else(|| parse_record_body(request), Ok)
}

fn parse_record_body(request: &AuthRequest) -> AuthResult<serde_json::Map<String, Value>> {
    let body = request.input_body()?;
    if let Some(Value::Object(mut body)) = body {
        let _ = body.remove("__proto__");
        return Ok(body);
    }
    let actual = match body {
        None => "undefined",
        Some(Value::Null) => "null",
        Some(Value::Bool(_)) => "boolean",
        Some(Value::Number(_)) => "number",
        Some(Value::String(_)) => "string",
        Some(Value::Array(_)) => "array",
        Some(Value::Object(_)) => "object",
    };
    Err(crate::AuthError::RequestValidation {
        message: format!("[body] Invalid input: expected record, received {actual}"),
    })
}

#[derive(Debug, Clone)]
pub(crate) struct EndpointBody {
    source: Option<Vec<u8>>,
    value: ValidatedInput,
}

#[derive(Debug, Clone)]
pub(crate) struct EndpointQuery {
    source: Option<Value>,
    value: ValidatedInput,
}

impl AuthRequest {
    fn parsed_input(&self) -> Option<FieldValue> {
        self.endpoint_body
            .as_ref()
            .filter(|body| body.source == self.body)
            .map(|body| body.value.field_value())
            .or_else(|| self.parsed_http_field_value())
    }

    fn current_input(&self) -> Option<FieldValue> {
        self.parsed_input()
            .or_else(|| self.raw_body_input.cached(&self.body))
    }

    // The HTTP media parser must select its policy before any hook decodes raw request bytes.
    pub(crate) fn hook_field_value(&self) -> FieldValue {
        self.current_input().unwrap_or_default()
    }

    /// Project JSON-only endpoint input without invoking `toJSON` or changing Request bytes.
    /// Use `input_field_value` to retain native values and handles.
    pub fn input_body(&self) -> AuthResult<Option<Value>> {
        crate::field_value::project_input_json(&self.input_field_value()?)
    }

    /// Share endpoint input without reading properties or crossing a JSON boundary.
    pub fn input_field_value(&self) -> AuthResult<FieldValue> {
        self.current_input()
            .map_or_else(|| self.raw_body_input.read(&self.body), Ok)
    }

    pub(crate) fn unvalidated_input(&self) -> AuthResult<ValidatedBody> {
        Ok(ValidatedBody::unvalidated_native(self.input_field_value()?))
    }

    /// Read the typed result installed by the matched route's body validator.
    pub fn validated_body<T: Send + Sync + 'static>(&self) -> Option<&T> {
        self.endpoint_body
            .as_ref()
            .filter(|body| body.source == self.body)?
            .value
            .typed
            .get()
    }

    pub fn set_endpoint_body(&mut self, value: ValidatedBody) {
        self.endpoint_body = Some(EndpointBody {
            source: self.body.clone(),
            value,
        });
    }

    /// Share endpoint query without reading properties or crossing a JSON boundary.
    pub fn input_query_field_value(&self) -> AuthResult<FieldValue> {
        self.endpoint_query
            .as_ref()
            .filter(|query| request_cache::same_query_source(&query.source, &self.query))
            .map_or_else(
                || self.raw_query_input.read(&self.query),
                |query| Ok(query.value.field_value()),
            )
    }

    /// Project endpoint query to JSON without invoking `toJSON` or replacing raw query input.
    /// Use `input_query_field_value` to retain undefined, Date, non-finite numbers, and identity.
    pub fn input_query(&self) -> AuthResult<Option<Value>> {
        crate::field_value::project_input_json(&self.input_query_field_value()?)
    }

    pub(crate) fn unvalidated_query(&self) -> AuthResult<ValidatedInput> {
        Ok(ValidatedInput::unvalidated_native(
            self.input_query_field_value()?,
        ))
    }

    /// Read the typed result installed by the matched route's query validator.
    pub fn validated_query<T: Send + Sync + 'static>(&self) -> Option<&T> {
        self.endpoint_query
            .as_ref()
            .filter(|query| request_cache::same_query_source(&query.source, &self.query))?
            .value
            .get()
    }

    /// Install query input while retaining the original query as the replacement guard.
    pub fn set_endpoint_query(&mut self, value: ValidatedInput) {
        self.endpoint_query = Some(EndpointQuery {
            source: self.query.clone(),
            value,
        });
    }

    pub(crate) fn projected_body(&self) -> Option<AuthResult<Option<Value>>> {
        self.parsed_input()
            .or_else(|| {
                self.body
                    .as_deref()
                    .filter(|bytes| !bytes.is_empty())
                    .and_then(|_| self.raw_body_input.cached(&self.body))
            })
            .map(|value| crate::field_value::project_input_json(&value))
    }
}

/// Returned before-hook input changes, applied after all before hooks complete.
#[derive(Debug, Clone, Default)]
pub struct EndpointInputPatch {
    /// Body changes retain the existing JSON patch contract.
    pub body: Option<Value>,
    /// Query changes retain native values until the matched schema consumes them.
    pub query: Option<FieldValue>,
}

impl EndpointInputPatch {
    /// Accumulate patches with recursive object merge, array replacement, and nullish omission.
    pub fn merge(&mut self, patch: Self) -> AuthResult<()> {
        merge_input(&mut self.body, patch.body);
        if let Some(patch) = patch
            .query
            .filter(|value| !value.is_null() && !value.is_undefined())
        {
            match &mut self.query {
                Some(current) => merge_field_value(current, patch)?,
                None => self.query = Some(patch),
            }
        }
        Ok(())
    }

    /// Install merged inputs without replacing the original transport body or query.
    pub fn apply(self, request: &mut AuthRequest) -> AuthResult<()> {
        if let Some(patch) = self.body {
            let mut body = request.unvalidated_input()?;
            merge_field_value(&mut body.projection, patch.into())?;
            request.set_endpoint_body(body);
        }
        if let Some(patch) = self.query {
            let mut query = request.unvalidated_query()?;
            merge_field_value(&mut query.projection, patch)?;
            request.set_endpoint_query(query);
        }
        Ok(())
    }
}

fn merge_field_value(target: &mut FieldValue, patch: FieldValue) -> AuthResult<()> {
    if matches!(patch, FieldValue::Undefined | FieldValue::Null) {
        return Ok(());
    }
    if let (FieldValue::Object(target), FieldValue::Object(patch)) = (&mut *target, &patch) {
        let mut fields = target.snapshot_fields()?;
        for (name, value) in patch.snapshot_fields()? {
            if matches!(value, FieldValue::Undefined | FieldValue::Null)
                || matches!(name.as_str(), "__proto__" | "constructor")
            {
                continue;
            }
            match fields.get_mut(&name) {
                Some(current) => merge_field_value(current, value)?,
                None => {
                    let _ = fields.insert(name, value);
                }
            }
        }
        *target = fields.into();
    } else {
        *target = patch;
    }
    Ok(())
}

fn merge_input(target: &mut Option<Value>, patch: Option<Value>) {
    if let Some(patch) = patch.filter(|value| !value.is_null()) {
        match target {
            Some(value) => merge_value(value, patch),
            None => *target = Some(patch),
        }
    }
}

fn merge_value(target: &mut Value, patch: Value) {
    if patch.is_null() {
        return;
    }
    if let (Value::Object(target), Value::Object(patch)) = (&mut *target, &patch) {
        for (name, value) in patch {
            if value.is_null() || matches!(name.as_str(), "__proto__" | "constructor") {
                continue;
            }
            match target.get_mut(name) {
                Some(current) => merge_value(current, value.clone()),
                None => {
                    let _ = target.insert(name.clone(), value.clone());
                }
            }
        }
    } else {
        *target = patch;
    }
}

/// Install handler inputs while preserving the raw scope for endpoint after hooks.
pub fn with_validated_input<T>(
    body: FieldValue,
    query: FieldValue,
    future: impl std::future::Future<Output = T>,
) -> impl std::future::Future<Output = T> {
    let future = Box::pin(future);
    async move {
        if let Some(mut context) = crate::hooks::current_request_hook_context() {
            context.body = body;
            context.query = query;
            crate::hooks::with_request_hook_context_value(context, future).await
        } else {
            future.await
        }
    }
}
