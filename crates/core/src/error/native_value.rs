use super::{ApiErrorClass, ApiErrorInit, AuthError, AuthResult, native};
use crate::FieldValue;

impl AuthError {
    /// Move an error into a native callback value without applying HTTP error sanitization.
    /// Existing thrown values retain their identity and do not evaluate properties.
    /// Typed errors expose their category and message; they have no JavaScript stack metadata.
    pub fn into_thrown_value(self) -> AuthResult<FieldValue> {
        if let Self::Response(error) = self {
            return Ok(error.value);
        }
        if self.is_api_error_instance(ApiErrorClass::BetterCall) {
            return native::construct(ApiErrorInit {
                class: if self.is_api_error_instance(ApiErrorClass::BetterAuth) {
                    ApiErrorClass::BetterAuth
                } else {
                    ApiErrorClass::BetterCall
                },
                status: self.status_value()?,
                body: self.body_value()?,
                ..Default::default()
            });
        }
        let name = match self {
            Self::TypeError(_) => "TypeError",
            Self::RangeError(_) => "RangeError",
            Self::DataClone => "DataCloneError",
            _ => "Error",
        };
        Ok(native::runtime_error(name, self.message_value()?))
    }
}
