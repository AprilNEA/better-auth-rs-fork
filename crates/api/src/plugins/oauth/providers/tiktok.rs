use better_auth_core::{AuthError, AuthResult};

use super::super::authorization::{AuthorizationRequest, RESERVED_PARAMS};
use super::OAuthProvider;

pub(in crate::plugins::oauth) fn authorization_url(
    provider: &OAuthProvider,
    input: AuthorizationRequest<'_>,
) -> AuthResult<String> {
    let mut url = url::Url::parse("https://www.tiktok.com/v2/auth/authorize")
        .map_err(|error| AuthError::internal(error.to_string()))?;
    let scopes = provider.social_scopes(input.scopes).join(",");
    let callback = provider
        .redirect_uri
        .as_deref()
        .filter(|value| !value.is_empty())
        .unwrap_or(input.callback_url);
    let _ = url.query_pairs_mut().extend_pairs([
        ("scope", scopes.as_str()),
        ("response_type", "code"),
        (
            "client_key",
            provider.client_key.as_deref().unwrap_or("undefined"),
        ),
        ("redirect_uri", callback),
        ("state", input.state),
    ]);
    for (key, value) in input.additional_params.into_iter().flatten() {
        if !RESERVED_PARAMS.contains(&key.as_str()) && key != "client_key" {
            let _ = url.query_pairs_mut().append_pair(key, value);
        }
    }
    Ok(url.to_string())
}
