use crate::{AuthError, AuthResult, FieldValue, Headers};
use std::{borrow::Cow, sync::Arc};

#[cfg(test)]
#[path = "response_body/http_tests.rs"]
mod http_tests;

/// Immutable Blob contents. Clones of a Blob response retain the same object identity.
#[derive(Debug)]
pub struct ResponseBlob {
    bytes: Arc<[u8]>,
    mime_type: String,
}

impl ResponseBlob {
    /// Apply the File API MIME normalization used by the Blob constructor.
    pub fn new(bytes: impl Into<Arc<[u8]>>, mime_type: impl Into<String>) -> Self {
        let mime_type = mime_type.into();
        let mime_type = if mime_type.bytes().all(|byte| (0x20..=0x7e).contains(&byte)) {
            mime_type.to_ascii_lowercase()
        } else {
            String::new()
        };
        Self {
            bytes: bytes.into(),
            mime_type,
        }
    }

    /// Borrow the Blob contents without changing the shared object.
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Read the normalized MIME type, which can be empty.
    pub fn mime_type(&self) -> &str {
        &self.mime_type
    }
}

/// One endpoint result, encoded only when a consumer requests an HTTP body.
#[derive(Debug, Clone)]
pub enum ResponseBody {
    Native(FieldValue),
    /// An ArrayBuffer or view, before HTTP materialization. Clones retain the same buffer.
    Binary(Arc<[u8]>),
    /// A shared Blob object, before HTTP materialization.
    Blob(Arc<ResponseBlob>),
    /// A null HTTP body, distinct from a present body with zero bytes.
    Empty,
    /// An explicit Response body or an already materialized HTTP body.
    Bytes(Vec<u8>),
}

impl ResponseBody {
    /// Read the current endpoint result. Byte replacements cross a JSON boundary.
    pub fn field_value(&self) -> AuthResult<FieldValue> {
        match self {
            Self::Empty => Ok(FieldValue::Undefined),
            Self::Native(value) => Ok(value.clone()),
            Self::Bytes(bytes) if bytes.is_empty() => Ok(FieldValue::Undefined),
            Self::Bytes(bytes) => FieldValue::parse_json(
                serde_json::from_slice::<&serde_json::value::RawValue>(bytes)?.get(),
            ),
            Self::Binary(_) | Self::Blob(_) => Err(AuthError::type_error(
                "Binary and Blob results are not field values",
            )),
        }
    }

    /// Project field values as JSON, or parse an encoded body without replacing the result.
    /// Binary and Blob values require explicit byte decoding because their native types are not field values.
    pub fn json(&self) -> AuthResult<Option<serde_json::Value>> {
        match self {
            Self::Empty => Ok(None),
            Self::Native(value) => value.json(),
            Self::Bytes(bytes) if bytes.is_empty() => Ok(None),
            Self::Bytes(bytes) => Ok(Some(serde_json::from_slice(bytes)?)),
            Self::Binary(_) | Self::Blob(_) => Err(AuthError::type_error(
                "Binary and Blob results do not have a JSON value",
            )),
        }
    }

    /// Encode the native result at an explicit byte boundary.
    pub fn bytes(&self) -> AuthResult<Cow<'_, [u8]>> {
        Ok(self.encode_http()?.0.unwrap_or(Cow::Borrowed(&[])))
    }

    fn encode_http(&self) -> AuthResult<(Option<Cow<'_, [u8]>>, HttpContentType<'_>)> {
        let (bytes, content_type) = match self {
            Self::Empty => (None, HttpContentType::Preserve),
            Self::Native(FieldValue::Undefined) => (None, HttpContentType::Json),
            Self::Native(FieldValue::String(value)) => (
                Some(Cow::Borrowed(value.as_bytes())),
                if value.is_empty() {
                    HttpContentType::Json
                } else {
                    HttpContentType::Set("text/plain")
                },
            ),
            Self::Native(FieldValue::Utf16String(value)) => (
                Some(Cow::Owned(
                    String::from_utf16_lossy(value.as_utf16()).into_bytes(),
                )),
                if value.as_utf16().is_empty() {
                    HttpContentType::Json
                } else {
                    HttpContentType::Set("text/plain")
                },
            ),
            Self::Native(FieldValue::Number(value)) if value.is_nan() => (
                Some(Cow::Borrowed(b"NaN".as_slice())),
                HttpContentType::Json,
            ),
            Self::Native(FieldValue::Function(_)) => {
                return Err(AuthError::type_error(
                    "Function results cannot be represented as an HTTP body",
                ));
            }
            Self::Native(value @ FieldValue::Object(object)) if !object_is_json(object)? => (
                Some(Cow::Owned(
                    String::from_utf16_lossy(value.display_utf16()?.as_utf16()).into_bytes(),
                )),
                HttpContentType::Preserve,
            ),
            Self::Native(value) => (
                crate::field_value::stringify_http(value)?
                    .map(|text| Cow::Owned(text.into_bytes())),
                HttpContentType::Json,
            ),
            Self::Binary(bytes) => (
                Some(Cow::Borrowed(bytes.as_ref())),
                HttpContentType::Set("application/octet-stream"),
            ),
            Self::Blob(blob) => (
                Some(Cow::Borrowed(blob.bytes())),
                HttpContentType::Set(if blob.mime_type().is_empty() {
                    "application/octet-stream"
                } else {
                    blob.mime_type()
                }),
            ),
            Self::Bytes(bytes) => (
                Some(Cow::Borrowed(bytes.as_slice())),
                HttpContentType::Preserve,
            ),
        };
        Ok((bytes, content_type))
    }

    pub fn into_bytes(self) -> AuthResult<Vec<u8>> {
        match self {
            Self::Bytes(bytes) => Ok(bytes),
            body => Ok(body.bytes()?.into_owned()),
        }
    }

    pub fn is_empty(&self) -> bool {
        match self {
            Self::Empty => true,
            Self::Native(FieldValue::String(value)) => value.is_empty(),
            Self::Native(FieldValue::Utf16String(value)) => value.as_utf16().is_empty(),
            Self::Native(value) => matches!(value, FieldValue::Undefined),
            Self::Binary(bytes) => bytes.is_empty(),
            Self::Blob(blob) => blob.bytes().is_empty(),
            Self::Bytes(bytes) => bytes.is_empty(),
        }
    }

    pub(crate) fn http_content_type(&self) -> &str {
        match self {
            Self::Native(value) if value.is_string() && value.is_truthy() => "text/plain",
            Self::Binary(_) => "application/octet-stream",
            Self::Blob(blob) if !blob.mime_type().is_empty() => blob.mime_type(),
            Self::Blob(_) => "application/octet-stream",
            Self::Native(_) | Self::Bytes(_) | Self::Empty => "application/json",
        }
    }

    pub(crate) fn into_http_body(self, headers: &mut Headers) -> AuthResult<Self> {
        if matches!(self, Self::Empty | Self::Bytes(_)) {
            return Ok(self);
        }
        let (bytes, content_type) = self.encode_http()?;
        let content_type = match content_type {
            HttpContentType::Json => Some("application/json"),
            HttpContentType::Set(value) => Some(value),
            HttpContentType::Preserve => None,
        };
        if let Some(content_type) = content_type {
            let _ = headers.insert("content-type", content_type);
        }
        Ok(bytes.map_or(Self::Empty, |bytes| Self::Bytes(bytes.into_owned())))
    }
}

enum HttpContentType<'a> {
    Json,
    Set(&'a str),
    Preserve,
}

fn object_is_json(object: &crate::FieldObject) -> AuthResult<bool> {
    if object.get("buffer")?.is_some_and(|value| value.is_truthy()) {
        return Ok(false);
    }
    // An absent own constructor resolves to Object.prototype.constructor. A getter still runs twice.
    if object
        .get("constructor")?
        .as_ref()
        .is_none_or(FieldValue::is_truthy)
    {
        let object_constructor = match object.get("constructor")? {
            None => true,
            Some(constructor) => constructor
                .model_property("name")?
                .strict_equals(&FieldValue::from("Object")),
        };
        if object_constructor {
            return Ok(true);
        }
    }
    Ok(matches!(
        object.get("toJSON")?,
        Some(FieldValue::Function(_))
    ))
}
