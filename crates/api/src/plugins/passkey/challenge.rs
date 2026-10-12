use better_auth_core::{AuthContext, AuthError, AuthRequest, AuthResult, AuthSchema, FieldValue};

use super::{
    PasskeyConfig,
    webauthn::{challenge_cookie_name, decode_challenge_cookie, get_cookie_value},
};

#[derive(Clone, Copy)]
pub(super) enum Ceremony {
    Registration,
    Authentication,
}

impl Ceremony {
    pub(super) fn name(&self) -> &'static str {
        match self {
            Self::Registration => "registration",
            Self::Authentication => "authentication",
        }
    }
}

pub(super) fn not_found() -> AuthError {
    AuthError::from_code("BAD_REQUEST", "CHALLENGE_NOT_FOUND", "Challenge not found")
}

pub(super) async fn consume<S: AuthSchema>(
    context: &AuthContext<S>,
    request: &AuthRequest,
    config: &PasskeyConfig,
    ceremony: Ceremony,
) -> AuthResult<FieldValue> {
    let cookie = get_cookie_value(request, &challenge_cookie_name(&context.config, config))
        .ok_or_else(not_found)?;
    let token = decode_challenge_cookie(&context.config, &cookie)
        .ok()
        .filter(|token| !token.is_empty())
        .ok_or_else(not_found)?;
    let challenge = context
        .database
        .consume_verification_by_identifier(&token)
        .await?
        .ok_or_else(not_found)?;
    let value = better_auth_core::utils::json::parse_native_json(&challenge.value.field_value())?;
    if !value
        .model_property("type")?
        .strict_equals(&ceremony.name().into())
    {
        return Err(not_found());
    }
    Ok(value)
}

pub(super) fn registration_value(
    challenge: &[u8],
    user: &super::PasskeyRegistrationUser,
    context: Option<String>,
) -> AuthResult<FieldValue> {
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
    use better_auth_core::FieldMap;
    FieldValue::from(FieldMap::from([
        ("type".into(), "registration".into()),
        (
            "expectedChallenge".into(),
            URL_SAFE_NO_PAD.encode(challenge).into(),
        ),
        (
            "userData".into(),
            FieldMap::from([
                ("id".into(), user.id.field_value()),
                ("name".into(), user.name.field_value()),
                ("displayName".into(), user.display_name.field_value()),
            ])
            .into(),
        ),
        (
            "context".into(),
            context.map_or(FieldValue::Null, FieldValue::from),
        ),
    ]))
    .stringify_native()
}

pub(super) fn authentication_value(
    challenge: &[u8],
    user_id: Option<&FieldValue>,
) -> AuthResult<FieldValue> {
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
    use better_auth_core::FieldMap;
    FieldValue::from(FieldMap::from([
        ("type".into(), "authentication".into()),
        (
            "expectedChallenge".into(),
            URL_SAFE_NO_PAD.encode(challenge).into(),
        ),
        (
            "userData".into(),
            FieldMap::from([(
                "id".into(),
                user_id
                    .filter(|id| id.is_truthy())
                    .cloned()
                    .unwrap_or_else(|| "".into()),
            )])
            .into(),
        ),
    ]))
    .stringify_native()
}

pub(super) fn registration_state(
    webauthn: &webauthn_rs_core::WebauthnCore,
    challenge: &FieldValue,
) -> AuthResult<webauthn_rs_core::proto::RegistrationState> {
    use webauthn_rs_core::proto::COSEAlgorithm;
    let builder = webauthn
        .new_challenge_register_builder(b"verification", "user", "user")
        .map_err(|error| AuthError::internal(error.to_string()))?
        .user_verification_policy(super::webauthn::VERIFICATION_POLICY)
        .credential_algorithms(vec![
            COSEAlgorithm::EDDSA,
            COSEAlgorithm::ES256,
            COSEAlgorithm::RS256,
        ]);
    let (_, state) = webauthn
        .generate_challenge_register(builder)
        .map_err(|error| AuthError::internal(error.to_string()))?;
    restore_challenge(state, challenge)
}

pub(super) fn authentication_state(
    webauthn: &webauthn_rs_core::WebauthnCore,
    challenge: &FieldValue,
    credential: webauthn_rs_core::proto::Credential,
) -> AuthResult<webauthn_rs_core::proto::AuthenticationState> {
    let builder = webauthn
        .new_challenge_authenticate_builder(
            vec![credential],
            Some(super::webauthn::VERIFICATION_POLICY),
        )
        .map_err(|error| AuthError::internal(error.to_string()))?
        .allow_backup_eligible_upgrade(true);
    let (_, state) = webauthn
        .generate_challenge_authenticate(builder)
        .map_err(|error| AuthError::internal(error.to_string()))?;
    restore_challenge(state, challenge)
}

fn restore_challenge<T: serde::Serialize + serde::de::DeserializeOwned>(
    state: T,
    challenge: &FieldValue,
) -> AuthResult<T> {
    // webauthn-rs-core 0.5.4 exposes its persistence format through Serde. Keep engine policy from its builders.
    let mut state = serde_json::to_value(state)?;
    state["challenge"] = challenge.decode::<String>()?.into();
    Ok(serde_json::from_value(state)?)
}
