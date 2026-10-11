//! HTTP profile bodies retain native values until a provider selects its profile or a legacy JSON bridge consumes it.

use better_auth_core::{AuthError, AuthResult, FieldValue};
use serde_json::{Value, value::RawValue};

pub(in crate::plugins::oauth) struct HttpProfile {
    pub data: FieldValue,
    pub error: FieldValue,
}

pub(in crate::plugins::oauth) async fn fetch_native(
    request: reqwest::RequestBuilder,
) -> AuthResult<HttpProfile> {
    let response = request.send().await.map_err(|error| {
        AuthError::internal(format!(
            "Failed to fetch user info: {}",
            error.without_url()
        ))
    })?;
    let status = response.status();
    let status_text = status_text(&response);
    let bytes = response.bytes().await.map_err(|error| {
        AuthError::internal(format!("Failed to read user info: {}", error.without_url()))
    })?;
    // Fetch decodes text as UTF-8 with replacement and removes a leading byte-order mark.
    let text = String::from_utf8_lossy(&bytes);
    let text = text.strip_prefix('\u{feff}').unwrap_or(&text);
    let (data, is_json) = parse_body(text)?;
    if status.is_success() {
        return Ok(HttpProfile {
            data,
            error: FieldValue::Null,
        });
    }
    let mut error = if is_json {
        data.enumerable_fields()?
    } else {
        Default::default()
    };
    let _ = error.insert("status".into(), f64::from(status.as_u16()).into());
    let _ = error.insert("statusText".into(), status_text.into());
    Ok(HttpProfile {
        data: FieldValue::Null,
        error: error.into(),
    })
}

fn parse_body(text: &str) -> AuthResult<(FieldValue, bool)> {
    match FieldValue::parse_json(text) {
        Ok(value) => Ok((value, true)),
        // better-fetch retains malformed JSON as text. A valid JSON value that exceeds the
        // native carrier's capabilities must still expose the conversion error.
        Err(error) if serde_json::from_str::<&RawValue>(text).is_ok() => Err(error),
        Err(_) => Ok((text.into(), false)),
    }
}

fn status_text(response: &reqwest::Response) -> String {
    if let Some(reason) = response.extensions().get::<hyper::ext::ReasonPhrase>() {
        return reason.as_bytes().iter().copied().map(char::from).collect();
    }
    if matches!(
        response.version(),
        reqwest::Version::HTTP_10 | reqwest::Version::HTTP_11
    ) {
        response
            .status()
            .canonical_reason()
            .unwrap_or_default()
            .into()
    } else {
        String::new()
    }
}

pub(in crate::plugins::oauth) async fn fetch_http_profile(
    request: reqwest::RequestBuilder,
) -> AuthResult<Option<Value>> {
    let response = fetch_native(request).await?;
    if response.error.is_truthy() {
        Ok(None)
    } else {
        response.data.json()
    }
}
