//! Native SimpleWebAuthn input checks precede the cryptographic engine's typed boundary.

use better_auth_core::{AuthError, AuthResult, FieldValue, Utf16String};
use webauthn_rs_core::proto::{
    AuthenticatorAssertionResponseRaw, AuthenticatorAttestationResponseRaw, PublicKeyCredential,
    RegisterPublicKeyCredential,
};

use super::challenge::Ceremony;

struct ClientResponse {
    id: FieldValue,
    response: FieldValue,
    client_data: Vec<u8>,
}

pub(super) fn authentication_response(
    response: &FieldValue,
    challenge: &FieldValue,
    origins: &[String],
) -> AuthResult<PublicKeyCredential> {
    let client = parse_client(response, challenge, origins, Ceremony::Authentication)?;
    let authenticator_data = client.response.model_property("authenticatorData")?;
    validate_base64url(&authenticator_data, "authenticatorData")?;
    let signature = client.response.model_property("signature")?;
    validate_base64url(&signature, "signature")?;
    let user_handle = client.response.model_property("userHandle")?;
    if user_handle.is_truthy() && !is_string(&user_handle) {
        return Err(AuthError::internal(
            "Credential response userHandle was not a string",
        ));
    }
    Ok(PublicKeyCredential {
        id: client.id.decode()?,
        raw_id: decode_base64url(&client.id)?.into(),
        response: AuthenticatorAssertionResponseRaw {
            authenticator_data: decode_base64url(&authenticator_data)?.into(),
            client_data_json: client.client_data.into(),
            signature: decode_base64url(&signature)?.into(),
            // Authentication does not consume userHandle; the callback retains the original response.
            user_handle: None,
        },
        extensions: Default::default(),
        type_: "public-key".into(),
    })
}

pub(super) fn registration_response(
    response: &FieldValue,
    challenge: &FieldValue,
    origins: &[String],
) -> AuthResult<RegisterPublicKeyCredential> {
    let client = parse_client(response, challenge, origins, Ceremony::Registration)?;
    let attestation_object =
        decode_base64url(&client.response.model_property("attestationObject")?)?;
    Ok(RegisterPublicKeyCredential {
        id: client.id.decode()?,
        raw_id: decode_base64url(&client.id)?.into(),
        response: AuthenticatorAttestationResponseRaw {
            attestation_object: attestation_object.into(),
            client_data_json: client.client_data.into(),
            transports: None,
        },
        type_: "public-key".into(),
        extensions: Default::default(),
    })
}

fn parse_client(
    response: &FieldValue,
    expected_challenge: &FieldValue,
    origins: &[String],
    ceremony: Ceremony,
) -> AuthResult<ClientResponse> {
    let id = response.model_property("id")?;
    let raw_id = response.model_property("rawId")?;
    let credential_type = response.model_property("type")?;
    let assertion = response.model_property("response")?;
    if !id.is_truthy() {
        return Err(AuthError::internal("Missing credential ID"));
    }
    if !id.strict_equals(&raw_id) {
        return Err(AuthError::internal(
            "Credential ID was not base64url-encoded",
        ));
    }
    if !credential_type.strict_equals(&"public-key".into()) {
        return Err(message(&[
            "Unexpected credential type ".into(),
            credential_type,
            ", expected \"public-key\"".into(),
        ])?);
    }
    let client_data = match (&ceremony, &assertion) {
        (Ceremony::Authentication, FieldValue::Undefined | FieldValue::Null) => {
            FieldValue::Undefined
        }
        _ => assertion.model_property("clientDataJSON")?,
    };
    if matches!(ceremony, Ceremony::Authentication) && !is_string(&client_data) {
        return Err(AuthError::internal(
            "Credential response clientDataJSON was not a string",
        ));
    }
    let client_data = decode_base64url(&client_data)?;
    let text = String::from_utf8_lossy(
        client_data
            .strip_prefix(&[0xef, 0xbb, 0xbf])
            .unwrap_or(&client_data),
    );
    let data = better_auth_core::utils::json::parse_native_json(&text.as_ref().into())?;
    let response_type = data.model_property("type")?;
    let expected_type = match ceremony {
        Ceremony::Registration => "webauthn.create",
        Ceremony::Authentication => "webauthn.get",
    };
    if !response_type.strict_equals(&expected_type.into()) {
        return Err(message(&[
            format!("Unexpected {} response type: ", ceremony.name()).into(),
            response_type,
        ])?);
    }
    let challenge = data.model_property("challenge")?;
    if !challenge.strict_equals(expected_challenge) {
        return Err(message(&[
            format!("Unexpected {} response challenge \"", ceremony.name()).into(),
            challenge,
            "\", expected \"".into(),
            expected_challenge.clone(),
            "\"".into(),
        ])?);
    }
    let origin = data.model_property("origin")?;
    if !origins
        .iter()
        .any(|allowed| origin.strict_equals(&allowed.as_str().into()))
    {
        return Err(message(&[
            format!("Unexpected {} response origin \"", ceremony.name()).into(),
            origin,
            match origins {
                [origin] => format!("\", expected \"{origin}\"").into(),
                _ => format!("\", expected one of: {}", origins.join(", ")).into(),
            },
        ])?);
    }
    Ok(ClientResponse {
        id,
        response: assertion,
        client_data,
    })
}

fn is_string(value: &FieldValue) -> bool {
    matches!(value, FieldValue::String(_) | FieldValue::Utf16String(_))
}

fn message(parts: &[FieldValue]) -> AuthResult<AuthError> {
    let mut units = Vec::new();
    for part in parts {
        units.extend_from_slice(part.display_utf16()?.as_utf16());
    }
    let error = AuthError::internal("").into_thrown_value()?;
    error.set_model_property("message", Utf16String::from_units(units).into())?;
    Ok(AuthError::from_thrown(error))
}

fn validate_base64url(value: &FieldValue, name: &str) -> AuthResult<()> {
    if !is_string(value) {
        return Err(AuthError::type_error("input.replace is not a function"));
    }
    let text = value.decode::<Utf16String>()?;
    let bytes = text
        .as_utf16()
        .iter()
        .filter(|unit| **unit != u16::from(b'='))
        .copied()
        .collect::<Vec<_>>();
    if bytes
        .iter()
        .all(|unit| matches!(*unit, 65..=90 | 97..=122 | 48..=57 | 45 | 95))
    {
        Ok(())
    } else {
        Err(AuthError::internal(format!(
            "Credential response {name} was not a base64url string"
        )))
    }
}

fn decode_base64url(value: &FieldValue) -> AuthResult<Vec<u8>> {
    // @hexagon/base64 uses a zero-filled lookup table and truncates the allocated buffer length.
    let text = value.decode::<Utf16String>()?;
    let units = text.as_utf16();
    let padding = units
        .iter()
        .rev()
        .take(2)
        .take_while(|unit| **unit == u16::from(b'='))
        .count();
    let length = (units.len() * 3 / 4).saturating_sub(padding);
    let sextet = |index: usize| -> u8 {
        match units.get(index).copied() {
            Some(unit @ 65..=90) => (unit - 65) as u8,
            Some(unit @ 97..=122) => (unit - 97 + 26) as u8,
            Some(unit @ 48..=57) => (unit - 48 + 52) as u8,
            Some(45) => 62,
            Some(95) => 63,
            _ => 0,
        }
    };
    let mut bytes = Vec::with_capacity(length);
    for offset in (0..units.len()).step_by(4) {
        let [a, b, c, d] = [
            sextet(offset),
            sextet(offset + 1),
            sextet(offset + 2),
            sextet(offset + 3),
        ];
        bytes.extend_from_slice(&[
            (a << 2) | (b >> 4),
            ((b & 15) << 4) | (c >> 2),
            ((c & 3) << 6) | (d & 63),
        ]);
    }
    bytes.truncate(length);
    Ok(bytes)
}
