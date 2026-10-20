use super::authorization::{AuthorizationRequest, build_authorization_url};
use super::provider_tokens::{
    refresh_tokens_via_provider, validate_authorization_code_via_provider,
};
use super::resolved::ResolvedProvider;
use super::{AppleClientSecretError, AppleClientSecretSigner, AppleOptions, OAuthProvider};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use better_auth_core::{AuthError, AuthRequest, HttpMethod};
use josekit::JoseHeader;
use josekit::jwk::KeyPair;
use josekit::jwk::alg::ec::{EcCurve, EcKeyPair};
use josekit::jws::ES256;
use serde_json::{Value, json};
use std::error::Error;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

const TEAM_ID: &str = "TEAM123456";
const KEY_ID: &str = "KEY1234567";
const CLIENT_ID: &str = "club.example.web";

struct KeyFixture {
    private_pem: Vec<u8>,
    public_pem: Vec<u8>,
}

fn key(curve: EcCurve) -> TestResult<KeyFixture> {
    let pair = EcKeyPair::generate(curve)?;
    Ok(KeyFixture {
        private_pem: pair.to_pem_private_key(),
        public_pem: pair.to_pem_public_key(),
    })
}

fn signer(key: &KeyFixture) -> TestResult<AppleClientSecretSigner> {
    Ok(AppleClientSecretSigner::new(
        TEAM_ID,
        KEY_ID,
        &key.private_pem,
    )?)
}

/// Read the JWT payload without signature or expiry checks.
fn payload(secret: &str) -> TestResult<Value> {
    let encoded = secret.split('.').nth(1).ok_or("Missing JWT payload")?;
    Ok(serde_json::from_slice(&URL_SAFE_NO_PAD.decode(encoded)?)?)
}

/// Verify the secret as Apple does: signature, header, and every claim.
fn verified(secret: &str, key: &KeyFixture, client_id: &str) -> TestResult<Value> {
    let verifier = ES256.verifier_from_pem(&key.public_pem)?;
    let (payload, header) = josekit::jwt::decode_with_verifier(secret, &verifier)?;
    assert_eq!(header.claim("alg"), Some(&json!("ES256")));
    assert_eq!(header.claim("kid"), Some(&json!(KEY_ID)));
    assert_eq!(header.claim("typ"), None);
    let claims = Value::Object(payload.claims_set().clone());
    assert_eq!(claims.get("iss"), Some(&json!(TEAM_ID)));
    assert_eq!(claims.get("sub"), Some(&json!(client_id)));
    assert_eq!(claims.get("aud"), Some(&json!("https://appleid.apple.com")));
    let now = chrono::Utc::now().timestamp();
    let issued = claims
        .get("iat")
        .and_then(Value::as_i64)
        .ok_or("Missing iat")?;
    let expires = claims
        .get("exp")
        .and_then(Value::as_i64)
        .ok_or("Missing exp")?;
    assert!(
        issued <= now && now < expires,
        "secret is not currently valid"
    );
    Ok(claims)
}

fn lifetime(claims: &Value) -> TestResult<i64> {
    let issued = claims
        .get("iat")
        .and_then(Value::as_i64)
        .ok_or("Missing iat")?;
    let expires = claims
        .get("exp")
        .and_then(Value::as_i64)
        .ok_or("Missing exp")?;
    Ok(expires - issued)
}

fn apple(client_secret: &str, signer: Option<AppleClientSecretSigner>) -> OAuthProvider {
    OAuthProvider::apple(
        CLIENT_ID,
        client_secret,
        AppleOptions {
            client_secret_signer: signer,
            ..AppleOptions::default()
        },
    )
}

#[test]
fn signer_issues_es256_secret_with_apple_claims() -> TestResult {
    let key = key(EcCurve::P256)?;
    let secret = signer(&key)?.client_secret(CLIENT_ID)?;
    let claims = verified(&secret, &key, CLIENT_ID)?;
    assert_eq!(lifetime(&claims)?, 3600);
    let mut keys: Vec<_> = claims
        .as_object()
        .ok_or("Claims must be an object")?
        .keys()
        .map(String::as_str)
        .collect();
    keys.sort_unstable();
    assert_eq!(keys, ["aud", "exp", "iat", "iss", "sub"]);
    Ok(())
}

#[test]
fn signer_reuses_secret_until_the_renewal_margin() -> TestResult {
    let signer = signer(&key(EcCurve::P256)?)?;
    let first = signer.client_secret_at(CLIENT_ID, 1_000)?;
    assert_eq!(signer.client_secret_at(CLIENT_ID, 1_000)?, first);
    // 301 seconds of validity remain, so the cached secret is still usable.
    assert_eq!(signer.client_secret_at(CLIENT_ID, 4_299)?, first);
    // Exactly 300 seconds remain, so the signer issues a new secret.
    let renewed = signer.client_secret_at(CLIENT_ID, 4_300)?;
    assert_ne!(renewed, first);
    assert_eq!(payload(&renewed)?.get("iat"), Some(&json!(4_300)));
    assert_eq!(signer.clone().client_secret_at(CLIENT_ID, 4_301)?, renewed);
    Ok(())
}

#[test]
fn signer_renews_for_another_client_or_an_earlier_clock() -> TestResult {
    let signer = signer(&key(EcCurve::P256)?)?;
    let first = signer.client_secret_at(CLIENT_ID, 2_000)?;
    let other = signer.client_secret_at("club.example.other", 2_000)?;
    assert_ne!(other, first);
    assert_eq!(
        payload(&other)?.get("sub"),
        Some(&json!("club.example.other"))
    );
    let earlier = signer.client_secret_at("club.example.other", 1_999)?;
    assert_ne!(earlier, other);
    assert_eq!(payload(&earlier)?.get("iat"), Some(&json!(1_999)));
    Ok(())
}

#[test]
fn lifetime_accepts_only_the_range_apple_allows() -> TestResult {
    let key = key(EcCurve::P256)?;
    for (seconds, accepted) in [
        (599, false),
        (600, true),
        (604_800, true),
        (15_777_000, true),
        (15_777_001, false),
    ] {
        let result = signer(&key)?.with_lifetime(Duration::from_secs(seconds));
        match result {
            Ok(signer) => {
                assert!(accepted, "{seconds}");
                let secret = signer.client_secret(CLIENT_ID)?;
                let claims = verified(&secret, &key, CLIENT_ID)?;
                assert_eq!(lifetime(&claims)?, i64::try_from(seconds)?);
            }
            Err(error) => {
                assert!(!accepted, "{seconds}");
                assert_eq!(error, AppleClientSecretError::InvalidLifetime);
            }
        }
    }
    Ok(())
}

#[test]
fn signer_rejects_incomplete_or_unusable_credentials() -> TestResult {
    let p256 = key(EcCurve::P256)?;
    let p384 = key(EcCurve::P384)?;
    for (team, key_id, pem, expected) in [
        (
            " ",
            KEY_ID,
            p256.private_pem.as_slice(),
            AppleClientSecretError::MissingTeamId,
        ),
        (
            TEAM_ID,
            "",
            p256.private_pem.as_slice(),
            AppleClientSecretError::MissingKeyId,
        ),
        (
            TEAM_ID,
            KEY_ID,
            b"not a key".as_slice(),
            AppleClientSecretError::InvalidPrivateKey,
        ),
        (
            TEAM_ID,
            KEY_ID,
            p256.public_pem.as_slice(),
            AppleClientSecretError::InvalidPrivateKey,
        ),
        (
            TEAM_ID,
            KEY_ID,
            p384.private_pem.as_slice(),
            AppleClientSecretError::InvalidPrivateKey,
        ),
    ] {
        let error = AppleClientSecretSigner::new(team, key_id, pem)
            .err()
            .ok_or("Invalid credentials were accepted")?;
        assert_eq!(error, expected);
    }
    Ok(())
}

#[test]
fn debug_output_omits_the_private_key() -> TestResult {
    let key = key(EcCurve::P256)?;
    let output = format!("{:?}", signer(&key)?);
    assert!(output.contains(TEAM_ID) && output.contains(KEY_ID));
    let pem = String::from_utf8(key.private_pem.clone())?;
    let body = pem.lines().nth(1).ok_or("Missing PEM body")?;
    assert!(!output.contains("PRIVATE KEY") && !output.contains(body));
    Ok(())
}

fn authorization_url(provider: OAuthProvider) -> Result<String, AuthError> {
    build_authorization_url(
        &ResolvedProvider {
            config: provider,
            generic: None,
        },
        AuthorizationRequest {
            callback_url: "https://app.example/api/auth/callback/apple",
            scopes: None,
            state: "state",
            code_challenge: "challenge",
            login_hint: None,
            nonce: None,
            additional_params: None,
        },
    )
}

#[test]
fn authorization_accepts_a_signer_instead_of_a_static_secret() -> TestResult {
    let signer = signer(&key(EcCurve::P256)?)?;
    let url = url::Url::parse(&authorization_url(apple("", Some(signer)))?)?;
    assert_eq!(url.host_str(), Some("appleid.apple.com"));
    assert!(url.query_pairs().all(|(name, _)| name != "client_secret"));
    let error = authorization_url(apple("", None))
        .err()
        .ok_or("A provider without a secret was accepted")?;
    assert!(
        matches!(error, AuthError::Internal(message) if message == "CLIENT_ID_AND_SECRET_REQUIRED")
    );
    Ok(())
}

/// Token endpoint that records each form body and returns a fixed token set.
struct TokenServer {
    url: String,
    bodies: Arc<Mutex<Vec<String>>>,
    task: tokio::task::JoinHandle<()>,
}

impl TokenServer {
    async fn start() -> TestResult<Self> {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let url = format!("http://{}/auth/token", listener.local_addr()?);
        let bodies = Arc::new(Mutex::new(Vec::new()));
        let captured = bodies.clone();
        let task = tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                let Ok(body) = read_body(&mut stream).await else {
                    continue;
                };
                captured
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .push(body);
                let response = json!({
                    "access_token": "apple-access",
                    "refresh_token": "apple-refresh",
                    "token_type": "bearer",
                    "expires_in": 3600,
                })
                .to_string();
                let _ = stream
                    .write_all(
                        format!(
                            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{response}",
                            response.len()
                        )
                        .as_bytes(),
                    )
                    .await;
            }
        });
        Ok(Self { url, bodies, task })
    }

    fn forms(&self) -> Vec<Vec<(String, String)>> {
        self.bodies
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .iter()
            .map(|body| {
                url::form_urlencoded::parse(body.as_bytes())
                    .into_owned()
                    .collect()
            })
            .collect()
    }
}

impl Drop for TokenServer {
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// Read one HTTP request and return its body, honoring `Content-Length`.
async fn read_body(stream: &mut tokio::net::TcpStream) -> std::io::Result<String> {
    let mut buffer = Vec::new();
    let mut chunk = [0; 4096];
    loop {
        let size = stream.read(&mut chunk).await?;
        if size == 0 {
            return Ok(String::new());
        }
        buffer.extend_from_slice(chunk.get(..size).unwrap_or_default());
        let Some(end) = buffer.windows(4).position(|window| window == b"\r\n\r\n") else {
            continue;
        };
        let head =
            String::from_utf8_lossy(buffer.get(..end).unwrap_or_default()).to_ascii_lowercase();
        let length = head
            .lines()
            .find_map(|line| line.strip_prefix("content-length:"))
            .and_then(|value| value.trim().parse::<usize>().ok())
            .unwrap_or(0);
        if let Some(body) = buffer.get(end + 4..end + 4 + length) {
            return Ok(String::from_utf8_lossy(body).into_owned());
        }
    }
}

fn field<'a>(form: &'a [(String, String)], name: &str) -> TestResult<&'a str> {
    form.iter()
        .find(|(key, _)| key == name)
        .map(|(_, value)| value.as_str())
        .ok_or_else(|| format!("Missing form field: {name}").into())
}

#[tokio::test]
async fn token_requests_send_the_generated_secret_instead_of_the_static_one() -> TestResult {
    let key = key(EcCurve::P256)?;
    let server = TokenServer::start().await?;
    let mut config = apple("static-secret", Some(signer(&key)?));
    config.token_url = server.url.clone();
    let provider = ResolvedProvider {
        config,
        generic: None,
    };

    let tokens = validate_authorization_code_via_provider(
        &provider,
        "apple-code",
        "https://app.example/api/auth/callback/apple",
        Some("verifier"),
        None,
    )
    .await?;
    assert_eq!(tokens.access_token.as_deref(), Some("apple-access"));
    let refreshed = refresh_tokens_via_provider(
        &provider,
        "apple-refresh",
        &AuthRequest::new(HttpMethod::Post, "/refresh-token"),
    )
    .await?;
    assert_eq!(refreshed.refresh_token.as_deref(), Some("apple-refresh"));

    let forms = server.forms();
    assert_eq!(forms.len(), 2);
    let mut secrets = Vec::new();
    for (form, grant) in forms.iter().zip(["authorization_code", "refresh_token"]) {
        assert_eq!(field(form, "grant_type")?, grant);
        assert_eq!(field(form, "client_id")?, CLIENT_ID);
        let secret = field(form, "client_secret")?;
        assert_ne!(secret, "static-secret");
        let claims = verified(secret, &key, CLIENT_ID)?;
        assert_eq!(lifetime(&claims)?, 3600);
        secrets.push(secret);
    }
    // Both requests fall inside one renewal window, so they share the cached secret.
    assert_eq!(secrets.first(), secrets.get(1));
    Ok(())
}
