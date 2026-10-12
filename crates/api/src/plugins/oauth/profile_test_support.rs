//! Observe the production provider value without reconstructing a typed response.
#![expect(
    clippy::expect_used,
    reason = "A contract observation must fail immediately when native access or JSON serialization fails."
)]

use better_auth_core::FieldValue;
use serde_json::Value;

use super::{
    OAuthTokenSet,
    resolved::ResolvedProvider,
    social_profile::{ProviderProfile, resolve_account_subject},
};

pub(super) fn json(profile: ProviderProfile) -> Value {
    profile
        .value
        .json()
        .expect("The native provider response must serialize")
        .expect("The native provider response must have a JSON value")
}

pub(super) fn property(profile: &ProviderProfile, name: &str) -> FieldValue {
    profile
        .value
        .model_property(name)
        .expect("The native provider property must be readable")
}

pub(super) fn user(profile: &ProviderProfile) -> Value {
    property(profile, "user")
        .json()
        .expect("The native provider user must serialize")
        .expect("The native provider user must have a JSON value")
}

pub(super) fn data(profile: &ProviderProfile) -> Value {
    property(profile, "data")
        .json()
        .expect("The native provider data must serialize")
        .expect("The native provider data must have a JSON value")
}

pub(super) async fn subject(
    provider: &ResolvedProvider,
    tokens: &OAuthTokenSet,
    profile: &ProviderProfile,
) -> FieldValue {
    resolve_account_subject(
        provider,
        &tokens.fields().into(),
        &property(profile, "data"),
        profile.legacy_subject.as_ref(),
    )
    .await
    .expect("The provider must resolve the fixture account subject")
}
