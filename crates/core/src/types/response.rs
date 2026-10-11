use super::*;

mod http_init;
mod json_wrapper;

#[cfg(test)]
#[path = "response/json_wrapper_tests.rs"]
mod json_wrapper_tests;

impl AuthResponse {
    fn metadata_mut(&mut self) -> &mut ResponseMetadata {
        self.metadata.get_or_insert_default()
    }

    fn take_explicit_response_headers(&mut self) -> Option<Headers> {
        self.metadata.as_mut()?.explicit_response_headers.take()
    }

    fn returned_headers_mut(&mut self) -> &mut Headers {
        self.metadata
            .as_mut()
            .and_then(|metadata| metadata.explicit_response_headers.as_mut())
            .unwrap_or(&mut self.headers)
    }

    /// Native `returnStatus` provenance, independent of the effective HTTP status.
    pub fn native_status(&self) -> NativeResponseStatus {
        self.native_status.clone()
    }

    pub(crate) fn set_native_status(&mut self, status: NativeResponseStatus) {
        if self.is_native()
            && let NativeResponseStatus::Present(crate::SchemaValue::Typed(value)) = &status
        {
            self.status = *value;
        }
        self.native_status = status;
    }

    /// Classify the returned value at the caller's current property-read boundary.
    pub fn is_api_error(&self) -> crate::AuthResult<bool> {
        match &self.body {
            crate::ResponseBody::Native(value) if self.is_native() => {
                crate::error::is_api_error_value(value)
            }
            _ => Ok(false),
        }
    }

    /// Read the returned error's current status without converting the native value.
    pub fn api_error_status(&self) -> crate::AuthResult<crate::SchemaValue<u16>> {
        Ok(crate::SchemaValue::from_field(
            self.body.field_value()?.model_property("statusCode")?,
        ))
    }

    /// Read the returned error's current body without serializing the error object.
    pub fn api_error_body(&self) -> crate::AuthResult<crate::FieldValue> {
        self.body.field_value()?.model_property("body")
    }

    /// Convert the error's explicit headers at the caller's HeadersInit boundary.
    pub fn api_error_headers(&self) -> crate::AuthResult<Headers> {
        let value = self.body.field_value()?.model_property("headers")?;
        let mut headers = Headers::new();
        http_init::copy_headers(&mut headers, &value)?;
        Ok(headers)
    }

    /// Endpoint headers captured on a thrown native API error.
    pub fn captured_headers(&self) -> crate::AuthResult<Option<Headers>> {
        self.captured_headers_value()
            .as_ref()
            .map(http_init::headers_init)
            .transpose()
    }

    /// Retain captured header identity without running HeadersInit conversion.
    pub fn captured_headers_value(&self) -> Option<crate::FieldValue> {
        self.metadata.as_ref()?.captured_headers.clone()
    }

    /// Read the headers owned by an explicit native response, separate from endpoint headers.
    pub fn explicit_response_headers(&self) -> Option<&Headers> {
        self.metadata.as_ref()?.explicit_response_headers.as_ref()
    }

    fn separate_explicit_response_headers(&mut self) {
        if !self.is_native() && self.explicit_response_headers().is_none() {
            let headers = std::mem::take(&mut self.headers);
            self.metadata_mut().explicit_response_headers = Some(headers);
        }
    }

    pub(crate) fn initialize_endpoint_headers(&mut self, mut headers: Headers) {
        if !headers.is_empty() {
            self.metadata_mut().init_headers_present = Some(true);
        }
        self.separate_explicit_response_headers();
        headers.merge(std::mem::take(&mut self.headers));
        self.headers = headers;
    }

    pub(crate) fn merge_endpoint_headers(&mut self, headers: Headers) {
        if !headers.is_empty() {
            self.metadata_mut().init_headers_present = Some(true);
        }
        self.separate_explicit_response_headers();
        self.headers.merge(headers);
    }

    /// Attach the endpoint header accumulator without changing the error's HTTP headers.
    pub fn capture_error_headers(&mut self, headers: Headers) {
        self.capture_native_error_headers(headers.into());
    }

    /// Attach native captured headers without evaluating their properties.
    pub fn capture_native_error_headers(&mut self, headers: crate::FieldValue) {
        self.metadata_mut().captured_headers = Some(headers);
    }

    pub(crate) fn set_endpoint_headers(&mut self, headers: Option<Headers>) {
        self.metadata_mut().init_headers_present = Some(headers.is_some());
        self.headers = headers.unwrap_or_default();
    }

    pub(crate) fn endpoint_headers_value(&self) -> crate::FieldValue {
        let present = self
            .metadata
            .as_ref()
            .and_then(|metadata| metadata.init_headers_present)
            .unwrap_or(!matches!(self.native_status, NativeResponseStatus::Absent));
        if present || !self.headers.is_empty() {
            self.headers.clone().into()
        } else {
            crate::FieldValue::Undefined
        }
    }

    /// Replace the returned JSON value while preserving native endpoint status and accumulated headers.
    pub fn replace_json<T: Serialize + ?Sized>(&mut self, value: &T) -> crate::AuthResult<()> {
        self.body = crate::ResponseBody::Native(crate::FieldValue::parse_json(
            &serde_json::to_string(value)?,
        )?);
        self.origin = ResponseOrigin::Json;
        self.metadata = None;
        self.set_native_status(self.native_status.clone());
        Ok(())
    }

    /// Replace the returned value while retaining native endpoint status and accumulated response headers.
    pub fn replace_returned(&mut self, mut returned: Self) {
        if returned.is_native()
            && matches!(
                returned.body,
                crate::ResponseBody::Native(crate::FieldValue::Undefined)
            )
        {
            self.headers.merge(returned.headers);
            return;
        }
        let headers_present = self.endpoint_headers_value().is_truthy()
            || returned.endpoint_headers_value().is_truthy();
        returned.set_native_status(self.native_status.clone());
        returned.metadata_mut().init_headers_present = Some(headers_present);
        returned.separate_explicit_response_headers();
        let mut headers = std::mem::take(&mut self.headers);
        headers.merge(std::mem::take(&mut returned.headers));
        returned.headers = headers;
        *self = returned;
    }

    pub(crate) fn prepare_before_return(&mut self, http: bool) {
        if http && self.origin == ResponseOrigin::Json {
            self.origin = ResponseOrigin::HttpBeforeJson;
        }
    }

    fn has_json_wrapper(&self) -> bool {
        self.origin == ResponseOrigin::HttpBeforeJson
    }

    pub(crate) fn stops_before_hooks(&self) -> bool {
        self.has_json_wrapper()
            || !self.is_native()
            || !matches!(&self.body,
                crate::ResponseBody::Native(value)
                    if !matches!(value, crate::FieldValue::Array(_) | crate::FieldValue::Object(_) | crate::FieldValue::Date(_))
            )
    }

    /// Construct an explicit HTTP response. Its own status does not set native endpoint status.
    pub fn new(status: u16) -> Self {
        Self {
            status,
            status_text: crate::Utf16String::default(),
            headers: Headers::new(),
            body: crate::ResponseBody::Empty,
            origin: ResponseOrigin::Explicit,
            metadata: None,
            native_status: NativeResponseStatus::Present(crate::SchemaValue::Undefined),
        }
    }

    /// Retain runtime fields until an HTTP consumer requests bytes.
    /// Pass `None` for an unset endpoint status, or a status code to set it explicitly.
    /// The active endpoint's `set_response_status` call takes precedence over this constructor's status.
    pub fn native(status: impl Into<NativeResponseStatus>, value: crate::FieldValue) -> Self {
        let mut response = Self::new(200);
        response.body = crate::ResponseBody::Native(value);
        response.origin = ResponseOrigin::Native;
        response.set_native_status(status.into());
        response
    }

    /// Return native binary data. Clones retain the supplied buffer until HTTP materialization.
    pub fn binary(
        status: impl Into<NativeResponseStatus>,
        bytes: impl Into<std::sync::Arc<[u8]>>,
    ) -> Self {
        let mut response = Self::native(status, crate::FieldValue::Undefined);
        response.body = crate::ResponseBody::Binary(bytes.into());
        response
    }

    /// Return a native Blob, including its MIME type and object identity.
    pub fn blob(
        status: impl Into<NativeResponseStatus>,
        blob: impl Into<std::sync::Arc<crate::ResponseBlob>>,
    ) -> Self {
        let mut response = Self::native(status, crate::FieldValue::Undefined);
        response.body = crate::ResponseBody::Blob(blob.into());
        response
    }

    /// Construct a native result from a Serde value; HTTP encoding depends on the resulting value type.
    /// `None` preserves an unset native status; a code sets it explicitly.
    /// The active endpoint's `set_response_status` call takes precedence over this constructor's status.
    pub fn json<T: Serialize>(
        status: impl Into<NativeResponseStatus>,
        data: &T,
    ) -> crate::AuthResult<Self> {
        Ok(Self::json_value(
            status,
            crate::FieldValue::parse_json(&serde_json::to_string(data)?)?,
        ))
    }

    /// Return `ctx.json` data without a Serde conversion or early JSON encoding.
    /// HTTP before hooks use strict JSON; endpoint and after-hook results use native HTTP encoding.
    pub fn json_value(status: impl Into<NativeResponseStatus>, value: crate::FieldValue) -> Self {
        let mut response = Self::native(status, value);
        response.origin = ResponseOrigin::Json;
        response
    }

    /// Construct an explicit text response with its own HTTP status.
    pub fn text(status: u16, text: impl Into<String>) -> Self {
        let body = crate::ResponseBody::Bytes(text.into().into_bytes());
        let mut headers = Headers::new();
        _ = headers.insert("content-type".to_string(), "text/plain".to_string());

        Self {
            status,
            status_text: crate::Utf16String::default(),
            headers,
            body,
            origin: ResponseOrigin::Explicit,
            metadata: None,
            native_status: NativeResponseStatus::Present(crate::SchemaValue::Undefined),
        }
    }

    /// Construct an explicit HTML response with its own HTTP status.
    pub fn html(status: u16, html: impl Into<String>) -> Self {
        let body = crate::ResponseBody::Bytes(html.into().into_bytes());
        let mut headers = Headers::new();
        _ = headers.insert(
            "content-type".to_string(),
            "text/html; charset=utf-8".to_string(),
        );

        Self {
            status,
            status_text: crate::Utf16String::default(),
            headers,
            body,
            origin: ResponseOrigin::Explicit,
            metadata: None,
            native_status: NativeResponseStatus::Present(crate::SchemaValue::Undefined),
        }
    }

    /// Materialize HTTP bytes and headers after endpoint hooks finish.
    /// Native results keep endpoint headers separate from explicit response headers.
    /// Match the pinned Bun Response constructor; the HTTP transport owns wire restrictions.
    pub fn into_http_response(mut self) -> crate::AuthResult<Self> {
        if !self.is_native() {
            if let Some(mut owned) = self.take_explicit_response_headers() {
                owned.merge(std::mem::take(&mut self.headers).into_response_init()?);
                self.headers = owned;
            }
            self.body = self.body.into_http_body(&mut self.headers)?;
            let status = f64::from(self.status).into();
            let status_text = self.status_text.clone().into();
            self.apply_http_init(&status, &status_text)?;
            return Ok(self);
        }
        if matches!(
            self.body,
            crate::ResponseBody::Bytes(_) | crate::ResponseBody::Empty
        ) {
            self.body = crate::ResponseBody::Native(self.body.field_value()?);
        }
        let mut init = http_init::HttpInit {
            headers: self.endpoint_headers_value(),
            status: self.native_status.field_value(),
            status_text: crate::FieldValue::Undefined,
        };
        if self.has_json_wrapper() {
            self.headers = http_init::headers_init(&init.headers)?;
            self.headers.strip_request_only();
            let _ = self.headers.insert("content-type", "application/json");
            self.body = self
                .body
                .field_value()?
                .stringify()?
                .map_or(crate::ResponseBody::Empty, |text| {
                    crate::ResponseBody::Bytes(text.into_bytes())
                });
            self.apply_http_init(&init.status, &init.status_text)?;
        } else {
            loop {
                if let crate::ResponseBody::Native(crate::FieldValue::Object(fields)) = &self.body
                    && fields.has_property("_flag")?
                    && fields
                        .get("_flag")?
                        .is_some_and(|flag| flag.strict_equals(&"json".into()))
                {
                    let fields = fields.clone();
                    self.materialize_json_wrapper(&fields, init)?;
                    break;
                }
                if let crate::ResponseBody::Native(value) = &self.body
                    && crate::error::is_api_error_value(value)?
                {
                    let body = value.model_property("body")?;
                    if http_init::nullish(&init.status) {
                        init.status = value.model_property("statusCode")?;
                    }
                    init.status_text = value.model_property("status")?.call_to_string()?;
                    if !init.headers.is_truthy() {
                        init.headers = value.model_property("headers")?;
                    }
                    self.body = crate::ResponseBody::Native(body);
                    continue;
                }
                self.headers = http_init::headers_init(&init.headers)?;
                self.headers.strip_request_only();
                self.body = self.body.into_http_body(&mut self.headers)?;
                self.apply_http_init(&init.status, &init.status_text)?;
                break;
            }
        }
        self.origin = ResponseOrigin::Explicit;
        Ok(self)
    }

    /// Whether this response retains a native endpoint value instead of an explicit HTTP Response.
    pub fn is_native(&self) -> bool {
        self.origin != ResponseOrigin::Explicit
    }

    /// Identify JSON by the effective HTTP MIME type, without parsing or projecting the body.
    /// A Blob with a JSON MIME type still requires byte decoding; its native value is a Blob.
    pub fn is_json(&self) -> bool {
        if self.is_native() {
            self.has_json_wrapper()
                || self
                    .body
                    .http_content_type()
                    .starts_with("application/json")
        } else {
            self.headers
                .get("content-type")
                .or_else(|| self.explicit_response_headers()?.get("content-type"))
                .is_some_and(|value| value.starts_with("application/json"))
        }
    }

    pub fn with_header(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        _ = self
            .returned_headers_mut()
            .insert(name.into(), value.into());
        self
    }

    pub fn with_appended_header(
        mut self,
        name: impl Into<String>,
        value: impl Into<String>,
    ) -> Self {
        self.returned_headers_mut()
            .append(name.into(), value.into());
        self
    }
}
