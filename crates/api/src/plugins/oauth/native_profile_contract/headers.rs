use super::*;
use base64::{Engine, engine::general_purpose::STANDARD};
use better_auth_core::Headers;
use hmac::{Hmac, Mac};
use sha2::Sha256;

pub(super) fn observe(headers: Option<&Headers>, state: &State) -> Value {
    let Some(headers) = headers else {
        return Value::Null;
    };
    let cookies: Vec<_> = headers.get_all("set-cookie").cloned().collect();
    let mut session_pair = None;
    for cookie in &cookies {
        let pair = cookie.split(';').next().unwrap();
        if !pair.starts_with("better-auth.session_token=") {
            assert!(
                pair.ends_with('='),
                "Only empty state cookies may accompany the Session cookie: {pair}"
            );
            continue;
        }
        let token = state
            .tracking
            .lock()
            .unwrap()
            .session_token
            .clone()
            .unwrap();
        let encoded = pair.strip_prefix("better-auth.session_token=").unwrap();
        let decoded = urlencoding::decode(encoded).unwrap();
        let (signed_token, signature) = decoded.rsplit_once('.').unwrap();
        assert_eq!(signed_token, token);
        let mut verifier = Hmac::<Sha256>::new_from_slice(SECRET.as_bytes()).unwrap();
        verifier.update(token.as_bytes());
        verifier
            .verify_slice(&STANDARD.decode(signature).unwrap())
            .unwrap();
        assert_eq!(encoded, urlencoding::encode(&decoded));
        session_pair = Some(pair.to_owned());
        state.tracking.lock().unwrap().replacements.insert(
            cookie.clone(),
            format!(
                "better-auth.session_token=<verified-session-token>{}",
                &cookie[pair.len()..]
            ),
        );
    }
    let mut entries: Vec<_> = headers
        .into_iter()
        .map(|(name, value)| {
            let name = name.to_ascii_lowercase();
            let value = if name == "set-cookie" {
                session_pair.as_ref().map_or_else(
                    || value.clone(),
                    |pair| {
                        value.replace(pair, "better-auth.session_token=<verified-session-token>")
                    },
                )
            } else {
                value.clone()
            };
            (name, value)
        })
        .collect();
    entries.sort_by(|left, right| left.0.cmp(&right.0));
    json!({"entries": entries, "cookies": cookies})
}
