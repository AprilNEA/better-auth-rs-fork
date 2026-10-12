pub(crate) use better_auth_core::wire::PasskeyView;
use serde::{Deserialize, Serialize};
use validator::Validate;

// -- Request types --

#[derive(Debug, Clone)]
pub(crate) struct VerifyRegistrationRequest {
    pub(super) response: better_auth_core::FieldValue,
    pub(super) name: Option<String>,
    pub(super) create_session: Option<bool>,
}

#[derive(Debug, Clone)]
pub(crate) struct VerifyAuthenticationRequest {
    pub(super) response: better_auth_core::FieldValue,
}

#[derive(Debug, Clone, Serialize, Deserialize, Validate)]
#[serde(rename_all = "camelCase")]
pub(crate) struct DeletePasskeyRequest {
    pub(super) id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Validate)]
#[serde(rename_all = "camelCase")]
pub(crate) struct UpdatePasskeyRequest {
    pub(super) id: String,
    #[validate(length(min = 1))]
    pub(super) name: String,
}

// -- Response helpers --

#[derive(Debug, Serialize)]
pub(crate) struct PasskeyResponse {
    pub(super) passkey: PasskeyView,
}

fn body_object(
    req: &better_auth_core::AuthRequest,
) -> better_auth_core::AuthResult<serde_json::Map<String, serde_json::Value>> {
    use crate::plugins::json_body;
    match req.input_body()? {
        Some(serde_json::Value::Object(value)) => Ok(value),
        value => Err(json_body::validation_error(&json_body::invalid_type(
            "body",
            "object",
            value.as_ref(),
        ))),
    }
}

fn native_body_object(
    req: &better_auth_core::AuthRequest,
) -> better_auth_core::AuthResult<better_auth_core::FieldValue> {
    let body = req.input_field_value()?;
    if body.as_object().is_none() {
        return Err(crate::plugins::json_body::validation_error(
            &crate::plugins::json_body::native_invalid_type("body", "object", Some(&body)),
        ));
    }
    Ok(body)
}

pub(super) fn trim_name(value: &str) -> &str {
    value.trim_matches(|character: char| {
        character == '\u{feff}' || (character.is_whitespace() && character != '\u{0085}')
    })
}

impl VerifyRegistrationRequest {
    pub(super) fn parse(req: &better_auth_core::AuthRequest) -> better_auth_core::AuthResult<Self> {
        use crate::plugins::json_body;
        if let Some(body) = req.validated_body::<Self>() {
            return Ok(body.clone());
        }
        let body = native_body_object(req)?;
        let response = body.model_property("response")?;
        let name = body.model_property("name")?;
        let create_session = body.model_property("createSession")?;
        let mut errors = Vec::new();
        if response.is_undefined() {
            errors.push(json_body::invalid_type(
                "body.response",
                "nonoptional",
                None,
            ));
        }
        errors.extend(
            [
                ("name", "string", &name),
                ("createSession", "boolean", &create_session),
            ]
            .into_iter()
            .filter_map(|(name, expected, value)| {
                (!value.is_undefined() && json_body::native_type_name(Some(value)) != expected)
                    .then(|| {
                        json_body::native_invalid_type(
                            &format!("body.{name}"),
                            expected,
                            Some(value),
                        )
                    })
            }),
        );
        if !errors.is_empty() {
            return Err(json_body::validation_error(&errors.join("; ")));
        }
        Ok(Self {
            response,
            name: if name.is_undefined() {
                None
            } else {
                Some(trim_name(&name.decode::<String>()?).to_owned())
            },
            create_session: if create_session.is_undefined() {
                None
            } else {
                Some(create_session.decode()?)
            },
        })
    }
}
impl VerifyAuthenticationRequest {
    pub(super) fn parse(req: &better_auth_core::AuthRequest) -> better_auth_core::AuthResult<Self> {
        use crate::plugins::json_body;
        if let Some(body) = req.validated_body::<Self>() {
            return Ok(body.clone());
        }
        let body = native_body_object(req)?;
        let response = body.model_property("response")?;
        match response.as_object() {
            Some(_) => Ok(Self {
                response: response.enumerable_fields()?.into(),
            }),
            None => Err(json_body::validation_error(
                &json_body::native_invalid_type("body.response", "record", Some(&response)),
            )),
        }
    }
}

fn projected<T: Serialize + Send + Sync + 'static>(
    body: T,
) -> better_auth_core::AuthResult<better_auth_core::endpoint_input::ValidatedBody> {
    Ok(better_auth_core::endpoint_input::ValidatedBody::new(
        Some(serde_json::to_value(&body)?),
        body,
    ))
}
pub(super) fn registration_body(
    req: &better_auth_core::AuthRequest,
) -> better_auth_core::AuthResult<better_auth_core::endpoint_input::ValidatedBody> {
    let body = VerifyRegistrationRequest::parse(req)?;
    let mut fields = better_auth_core::FieldMap::from([("response".into(), body.response.clone())]);
    if let Some(name) = &body.name {
        let _ = fields.insert("name".into(), name.clone().into());
    }
    if let Some(create_session) = body.create_session {
        let _ = fields.insert("createSession".into(), create_session.into());
    }
    Ok(better_auth_core::endpoint_input::ValidatedBody::native(
        fields.into(),
        body,
    ))
}
pub(super) fn authentication_body(
    req: &better_auth_core::AuthRequest,
) -> better_auth_core::AuthResult<better_auth_core::endpoint_input::ValidatedBody> {
    let body = VerifyAuthenticationRequest::parse(req)?;
    let fields = better_auth_core::FieldMap::from([("response".into(), body.response.clone())]);
    Ok(better_auth_core::endpoint_input::ValidatedBody::native(
        fields.into(),
        body,
    ))
}
pub(super) fn deletion_body(
    req: &better_auth_core::AuthRequest,
) -> better_auth_core::AuthResult<better_auth_core::endpoint_input::ValidatedBody> {
    let (body, _) =
        crate::plugins::json_body::string_input::<DeletePasskeyRequest>(req, &[("id", true)])?;
    projected(body)
}
pub(super) fn update_body(
    req: &better_auth_core::AuthRequest,
) -> better_auth_core::AuthResult<better_auth_core::endpoint_input::ValidatedBody> {
    use crate::plugins::json_body;
    let body = body_object(req)?;
    let mut errors = Vec::new();
    for name in ["id", "name"] {
        match body.get(name) {
            Some(serde_json::Value::String(value))
                if name == "name" && trim_name(value).is_empty() =>
            {
                errors.push(
                    "[body.name] Too small: expected string to have >=1 characters".to_owned(),
                )
            }
            Some(serde_json::Value::String(_)) => {}
            value => errors.push(json_body::invalid_type(
                &format!("body.{name}"),
                "string",
                value,
            )),
        }
    }
    if !errors.is_empty() {
        return Err(json_body::validation_error(&errors.join("; ")));
    }
    let mut typed: UpdatePasskeyRequest = serde_json::from_value(serde_json::Value::Object(body))?;
    typed.name = trim_name(&typed.name).to_owned();
    projected(typed)
}
pub(super) fn read<T: Clone + Send + Sync + 'static>(
    req: &better_auth_core::AuthRequest,
    validator: fn(
        &better_auth_core::AuthRequest,
    )
        -> better_auth_core::AuthResult<better_auth_core::endpoint_input::ValidatedBody>,
) -> better_auth_core::AuthResult<T> {
    if let Some(body) = req.validated_body::<T>() {
        return Ok(body.clone());
    }
    validator(req)?.get::<T>().cloned().ok_or_else(|| {
        better_auth_core::AuthError::internal(
            "Passkey body validator returned a different input type",
        )
    })
}
