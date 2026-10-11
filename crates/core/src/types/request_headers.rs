use super::{AuthRequest, Headers};
use crate::{AuthError, AuthResult, FieldArray, FieldValue, field_value::FieldArraySource};
use std::sync::{Arc, Mutex, MutexGuard};

#[derive(Debug)]
pub(super) struct ResponseHeaders {
    headers: Arc<Mutex<Headers>>,
    value: FieldValue,
}

impl Default for ResponseHeaders {
    fn default() -> Self {
        let headers = Arc::new(Mutex::new(Headers::new()));
        let value = FieldArray::from_source(Arc::new(HeaderPairs(headers.clone()))).into();
        Self { headers, value }
    }
}

struct HeaderPairs(Arc<Mutex<Headers>>);

fn lock_headers(headers: &Mutex<Headers>) -> AuthResult<MutexGuard<'_, Headers>> {
    headers
        .lock()
        .map_err(|_| AuthError::internal("Session response headers lock poisoned"))
}

impl FieldArraySource for HeaderPairs {
    fn len(&self) -> AuthResult<usize> {
        Ok(lock_headers(&self.0)?.0.len())
    }

    fn own_indices(&self) -> AuthResult<Vec<usize>> {
        Ok((0..self.len()?).collect())
    }

    fn get(&self, index: usize) -> AuthResult<Option<FieldValue>> {
        Ok(lock_headers(&self.0)?
            .0
            .get(index)
            .map(|(name, value)| FieldValue::from(vec![name.clone().into(), value.clone().into()])))
    }

    fn identity(&self) -> usize {
        Arc::as_ptr(&self.0) as usize
    }
}

impl AuthRequest {
    fn with_response_headers<T>(&self, apply: impl FnOnce(&mut Headers) -> T) -> AuthResult<T> {
        let binding = self
            .response_headers
            .lock()
            .map_err(|_| AuthError::internal("Session response headers lock poisoned"))?;
        let mut headers = lock_headers(&binding.headers)?;
        Ok(apply(&mut headers))
    }

    fn take_response_header_binding(&self) -> AuthResult<ResponseHeaders> {
        let mut binding = self
            .response_headers
            .lock()
            .map_err(|_| AuthError::internal("Session response headers lock poisoned"))?;
        // Retained native handles own the old collection after the request starts a new accumulator.
        Ok(std::mem::take(&mut *binding))
    }

    /// Queue a response header from request-scoped authentication middleware.
    pub fn set_response_header(&self, name: &str, value: impl Into<String>) -> AuthResult<()> {
        let value = value.into();
        self.with_response_headers(|headers| {
            let _ = headers.insert(name, value);
        })
    }

    /// Append a response header without replacing earlier values.
    pub fn append_response_header(&self, name: &str, value: String) -> AuthResult<()> {
        self.with_response_headers(|headers| headers.append(name, value))
    }

    pub(crate) fn has_response_cookie(&self, name: &str) -> AuthResult<bool> {
        self.with_response_headers(|headers| headers.has_set_cookie(name))
    }

    pub(crate) fn remove_response_cookie(&self, name: &str) -> AuthResult<()> {
        self.with_response_headers(|headers| headers.remove_set_cookie(name))
    }

    /// Borrow the current response header collection as a stable native HeadersInit handle.
    /// Cloned handles observe header mutations until the request starts a new accumulator.
    pub fn response_headers_value(&self) -> AuthResult<FieldValue> {
        Ok(self
            .response_headers
            .lock()
            .map_err(|_| AuthError::internal("Session response headers lock poisoned"))?
            .value
            .clone())
    }

    /// Construct an endpoint redirect with the current response header identity.
    pub fn redirect(&self, location: impl Into<String>) -> AuthResult<AuthError> {
        self.set_response_header("location", location)?;
        AuthError::try_api_error(crate::ApiErrorInit {
            status: "FOUND".into(),
            headers: self.response_headers_value()?,
            class: crate::ApiErrorClass::BetterCall,
            ..Default::default()
        })
    }

    /// Take the current response headers without draining retained native handles.
    pub fn take_response_headers(&self) -> AuthResult<Headers> {
        let binding = self.take_response_header_binding()?;
        let headers = lock_headers(&binding.headers)?.clone();
        Ok(headers)
    }

    #[doc(hidden)]
    pub fn take_response_headers_value(&self) -> AuthResult<FieldValue> {
        Ok(self.take_response_header_binding()?.value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redirect_retains_endpoint_header_identity_and_constructor_class() -> AuthResult<()> {
        let request = AuthRequest::new(crate::HttpMethod::Get, "/callback/provider");
        request.append_response_header("set-cookie", "state=; Max-Age=0".into())?;
        let headers = request.response_headers_value()?;
        let error = request.redirect("/welcome")?;
        assert!(error.headers_value()?.strict_equals(&headers));
        assert!(error.is_api_error_instance(crate::ApiErrorClass::BetterCall));
        assert!(!error.is_api_error_instance(crate::ApiErrorClass::BetterAuth));
        request.append_response_header("set-cookie", "after=1".into())?;
        let captured = request.take_response_headers()?;
        assert_eq!(
            Headers::from_field_value(&error.headers_value()?)?,
            captured
        );
        assert_eq!(captured.get_all("set-cookie").count(), 2);
        assert_eq!(
            captured.get("location").map(String::as_str),
            Some("/welcome")
        );
        Ok(())
    }
}
