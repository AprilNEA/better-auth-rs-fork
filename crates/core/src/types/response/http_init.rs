use crate::{AuthError, AuthResponse, AuthResult, FieldValue, Headers, Utf16String};

pub(super) struct HttpInit {
    pub headers: FieldValue,
    pub status: FieldValue,
    pub status_text: FieldValue,
}

impl AuthResponse {
    pub(super) fn apply_http_init(
        &mut self,
        status: &FieldValue,
        status_text: &FieldValue,
    ) -> AuthResult<()> {
        self.status = if status.is_undefined() {
            200
        } else {
            let value = crate::query::field_number(status)?;
            let number = if status.is_number() {
                value as i64
            } else {
                // Bun converts non-number statuses through ToInt32 before validating the Int64 result.
                let unsigned = if value.is_finite() {
                    value.trunc().rem_euclid(4_294_967_296.0) as u32
                } else {
                    0
                };
                i64::from(unsigned as i32)
            };
            if number != 101 && !(200..=599).contains(&number) {
                return Err(AuthError::RangeError(format!(
                    "The status provided ({number}) must be 101 or in the range of [200, 599]"
                )));
            }
            number as u16
        };
        self.status_text = if status_text.is_truthy() {
            status_text.display_utf16()?
        } else {
            Utf16String::default()
        };
        Ok(())
    }
}

impl Headers {
    /// Convert a native HeadersInit using the HTTP runtime's ordered conversion and validation.
    pub fn from_field_value(value: &FieldValue) -> AuthResult<Self> {
        headers_init(value)
    }

    pub(crate) fn into_response_init(self) -> AuthResult<Self> {
        let mut headers = Self::new();
        for (name, value) in self {
            append_header(
                &mut headers,
                &name.encode_utf16().collect::<Vec<_>>(),
                &value.encode_utf16().collect::<Vec<_>>(),
            )?;
        }
        // new Headers(init.headers) validates even request-only fields before better-call strips them.
        headers.strip_request_only();
        Ok(headers)
    }
}

pub(super) fn nullish(value: &FieldValue) -> bool {
    value.is_null() || value.is_undefined()
}

pub(super) fn optional_property(value: &FieldValue, name: &str) -> AuthResult<FieldValue> {
    if nullish(value) {
        Ok(FieldValue::Undefined)
    } else {
        value.model_property(name)
    }
}

pub(super) fn copy_headers(target: &mut Headers, value: &FieldValue) -> AuthResult<()> {
    if value.is_truthy() {
        target.merge(headers_init(value)?);
    }
    Ok(())
}

pub(super) fn headers_init(value: &FieldValue) -> AuthResult<Headers> {
    if nullish(value) {
        return Ok(Headers::new());
    }
    let mut converted: Vec<Vec<Utf16String>> = Vec::new();
    if let Some(pairs) = value.as_array() {
        let mut index = 0;
        while index < pairs.len()? {
            let pair = pairs.get(index)?.unwrap_or_default();
            let pair = pair
                .as_array()
                .ok_or_else(|| AuthError::type_error("Type error"))?;
            let mut fields = Vec::new();
            let mut field_index = 0;
            while field_index < pair.len()? {
                fields.push(pair.get(field_index)?.unwrap_or_default().display_utf16()?);
                field_index += 1;
            }
            converted.push(fields);
            index += 1;
        }
    } else if let Some(fields) = value.as_object() {
        for name in fields.own_keys()? {
            if !fields
                .own_property_descriptor(&name)?
                .is_some_and(|descriptor| descriptor.enumerable)
            {
                continue;
            }
            let value = fields.get(&name)?.unwrap_or_default().display_utf16()?;
            converted.push(vec![name.into(), value]);
        }
    } else if !matches!(value, FieldValue::Date(_) | FieldValue::Function(_)) {
        return Err(AuthError::type_error("Type error"));
    }
    // Bun converts the complete HeadersInit to DOMString values before validating any header.
    let mut headers = Headers::new();
    for pair in converted {
        let [name, value] = pair.as_slice() else {
            return Err(AuthError::type_error(
                "Header sub-sequence must contain exactly two items",
            ));
        };
        append_header(&mut headers, name.as_utf16(), value.as_utf16())?;
    }
    Ok(headers)
}

fn append_header(headers: &mut Headers, name: &[u16], value: &[u16]) -> AuthResult<()> {
    let name = String::from_utf16_lossy(name);
    if name.is_empty()
        || !name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&byte))
    {
        return Err(AuthError::type_error(format!(
            "Invalid header name: '{name}'"
        )));
    }
    let text = String::from_utf16_lossy(value);
    let value = text.trim_matches([' ', '\t', '\r', '\n']);
    if value
        .encode_utf16()
        .any(|unit| matches!(unit, 0 | 10 | 13) || unit > 255)
    {
        let error_name = BUN_HEADER_NAMES
            .iter()
            .copied()
            .find(|canonical| canonical.eq_ignore_ascii_case(&name))
            .unwrap_or(&name);
        return Err(AuthError::type_error(format!(
            "Header '{error_name}' has invalid value: '{value}'"
        )));
    }
    let name = name.to_ascii_lowercase();
    if name == "set-cookie" {
        headers.append(name, value);
    } else {
        let value = headers.get(&name).map_or_else(
            || value.to_owned(),
            |previous| {
                if name == "cookie" {
                    format!("{previous}; {value}")
                } else {
                    format!("{previous}, {value}")
                }
            },
        );
        let _ = headers.insert(name, value);
    }
    Ok(())
}

// Canonical names from Bun 1.4.2 (744846f84), src/jsc/bindings/webcore/HTTPHeaderNames.cpp.
// FetchHeaders uses this complete table only when formatting known-header value errors.
const BUN_HEADER_NAMES: &[&str] = &[
    "Accept",
    "Accept-Charset",
    "Accept-Encoding",
    "Accept-Language",
    "Accept-Ranges",
    "Access-Control-Allow-Credentials",
    "Access-Control-Allow-Headers",
    "Access-Control-Allow-Methods",
    "Access-Control-Allow-Origin",
    "Access-Control-Expose-Headers",
    "Access-Control-Max-Age",
    "Access-Control-Request-Headers",
    "Access-Control-Request-Method",
    "Age",
    "Authorization",
    "Cache-Control",
    "Connection",
    "Content-Disposition",
    "Content-Encoding",
    "Content-Language",
    "Content-Length",
    "Content-Location",
    "Content-Range",
    "Content-Security-Policy",
    "Content-Security-Policy-Report-Only",
    "Content-Type",
    "Cookie",
    "Cookie2",
    "Cross-Origin-Embedder-Policy",
    "Cross-Origin-Embedder-Policy-Report-Only",
    "Cross-Origin-Opener-Policy",
    "Cross-Origin-Opener-Policy-Report-Only",
    "Cross-Origin-Resource-Policy",
    "DNT",
    "Date",
    "Default-Style",
    "ETag",
    "Expect",
    "Expires",
    "Host",
    "Icy-MetaInt",
    "Icy-Metadata",
    "If-Match",
    "If-Modified-Since",
    "If-None-Match",
    "If-Range",
    "If-Unmodified-Since",
    "Keep-Alive",
    "Last-Event-ID",
    "Last-Modified",
    "Link",
    "Location",
    "Origin",
    "Ping-From",
    "Ping-To",
    "Pragma",
    "Proxy-Authorization",
    "Proxy-Connection",
    "Purpose",
    "Range",
    "Referer",
    "Referrer-Policy",
    "Refresh",
    "Report-To",
    "Sec-Fetch-Dest",
    "Sec-Fetch-Mode",
    "Sec-WebSocket-Accept",
    "Sec-WebSocket-Extensions",
    "Sec-WebSocket-Key",
    "Sec-WebSocket-Protocol",
    "Sec-WebSocket-Version",
    "Server-Timing",
    "Service-Worker",
    "Service-Worker-Allowed",
    "Service-Worker-Navigation-Preload",
    "Set-Cookie",
    "Set-Cookie2",
    "SourceMap",
    "Strict-Transport-Security",
    "TE",
    "Timing-Allow-Origin",
    "Trailer",
    "Transfer-Encoding",
    "Upgrade",
    "Upgrade-Insecure-Requests",
    "User-Agent",
    "Vary",
    "Via",
    "X-Content-Type-Options",
    "X-DNS-Prefetch-Control",
    "X-Frame-Options",
    "X-SourceMap",
    "X-Temp-Tablet",
    "X-XSS-Protection",
];

impl From<Headers> for FieldValue {
    fn from(headers: Headers) -> Self {
        headers
            .into_iter()
            .map(|(name, value)| FieldValue::from(vec![name.into(), value.into()]))
            .collect::<Vec<_>>()
            .into()
    }
}
