use super::{OAuthUserInfo, OAuthUserInfoRequest};
use better_auth_core::{AuthError, AuthResult, FieldValue, SchemaValue};
use serde_json::Value;

use crate::plugins::oauth::{OAuthProfileMapper, social_profile::ProviderProfile};

#[path = "default_profile.rs"]
mod native;

#[derive(Clone)]
pub(super) enum ProviderKind {
    Apple(super::apple::AppleOptions),
    Facebook(super::facebook::FacebookOptions),
    Cognito(super::super::CognitoOptions),
    Microsoft {
        options: super::microsoft::MicrosoftOptions,
        token_endpoint_auth: Option<super::TokenEndpointAuth>,
    },
    Paybin {
        issuer: String,
    },
    Custom,
    PayPal,
    Google {
        jwks_url: String,
        options: super::super::GoogleOptions,
    },
    GitHub {
        user_url: String,
        emails_url: String,
    },
    Discord,
    GitLab,
    Spotify,
    HuggingFace,
    Polar,
    Railway,
    Roblox,
    Notion,
    Twitch(super::twitch::TwitchOptions),
    Vercel,

    Figma,
    Dropbox,
    Kick,
    LinkedIn,
    Line {
        verify_url: String,
    },
    Slack,
    Naver,
    Linear,
    Atlassian,
    Reddit,
    Kakao,
    Zoom {
        pkce: bool,
    },
    Cloudflare,
    Salesforce,
    Twitter,
    TikTok,
    Vk,
    WeChat {
        refresh_url: String,
    },
}

impl ProviderKind {
    pub(super) fn account_subject(&self, profile: &FieldValue) -> AuthResult<Option<FieldValue>> {
        let field = match self {
            Self::Custom => return Ok(None),
            Self::Apple(_)
            | Self::Cognito(_)
            | Self::Google { .. }
            | Self::Paybin { .. }
            | Self::HuggingFace
            | Self::Railway
            | Self::Roblox
            | Self::Twitch(_)
            | Self::Vercel
            | Self::LinkedIn
            | Self::Line { .. } => "sub",
            Self::GitHub { .. }
            | Self::Discord
            | Self::GitLab
            | Self::Spotify
            | Self::Polar
            | Self::Notion
            | Self::Figma
            | Self::Kakao
            | Self::Zoom { .. }
            | Self::Cloudflare
            | Self::Reddit
            | Self::Linear => "id",
            Self::Microsoft { .. } => "oid",
            Self::Atlassian | Self::Dropbox => "account_id",
            Self::Salesforce | Self::Kick | Self::PayPal => "user_id",
            Self::Slack => "https://slack.com/user_id",
            Self::Naver => {
                return profile
                    .model_property("response")?
                    .model_property("id")
                    .map(Some);
            }
            Self::Twitter => {
                return profile
                    .model_property("data")?
                    .model_property("id")
                    .map(Some);
            }
            Self::TikTok => {
                return profile
                    .model_property("data")?
                    .model_property("user")?
                    .model_property("open_id")
                    .map(Some);
            }
            Self::Vk => {
                return profile
                    .model_property("user")?
                    .model_property("user_id")
                    .map(Some);
            }
            Self::WeChat { .. } => {
                let unionid = profile.model_property("unionid")?;
                return if unionid.is_truthy() {
                    Ok(Some(unionid))
                } else {
                    profile.model_property("openid").map(Some)
                };
            }
            Self::Facebook(_) => {
                let has_sub = match profile {
                    FieldValue::Object(object) => object.has_property("sub")?,
                    FieldValue::Array(_) | FieldValue::Date(_) | FieldValue::Function(_) => false,
                    _ => {
                        return Err(AuthError::type_error(
                            "Cannot use 'in' operator to search for 'sub'",
                        ));
                    }
                };
                if has_sub { "sub" } else { "id" }
            }
        };
        profile.model_property(field).map(Some)
    }

    pub(super) fn scopes(&self) -> &'static [&'static str] {
        match self {
            Self::Apple(_) => &["email", "name"],
            Self::Facebook(_) => &["email", "public_profile"],
            Self::Microsoft { .. } => {
                &["openid", "profile", "email", "User.Read", "offline_access"]
            }
            Self::Custom | Self::Vercel | Self::Zoom { .. } | Self::PayPal | Self::Notion => &[],
            Self::Google { .. } => &["email", "profile", "openid"],
            Self::GitHub { .. } => &["read:user", "user:email"],
            Self::Discord => &["identify", "email"],
            Self::GitLab => &["read_user"],
            Self::Spotify => &["user-read-email"],
            Self::HuggingFace
            | Self::Polar
            | Self::Slack
            | Self::Cognito(_)
            | Self::Line { .. } => &["openid", "profile", "email"],
            Self::Figma => &["current_user:read"],
            Self::Dropbox => &["account_info.read"],
            Self::Kick => &["user:read"],
            Self::LinkedIn => &["profile", "email", "openid"],
            Self::Naver => &["profile", "email"],
            Self::Linear => &["read"],
            Self::Atlassian => &["read:jira-user", "offline_access"],
            Self::Reddit => &["identity"],
            Self::Kakao => &["account_email", "profile_image", "profile_nickname"],
            Self::Cloudflare => &["user-details.read"],
            Self::Salesforce | Self::Paybin { .. } | Self::Railway => {
                &["openid", "email", "profile"]
            }
            Self::Roblox => &["openid", "profile"],
            Self::Twitch(_) => &["user:read:email", "openid"],
            Self::Twitter => &["users.read", "tweet.read", "offline.access", "users.email"],
            Self::TikTok => &["user.info.profile"],
            Self::Vk => &["email", "phone"],
            Self::WeChat { .. } => &["snsapi_login"],
        }
    }
    pub(super) fn decode_profile(&self, profile: Value) -> AuthResult<Option<OAuthUserInfo>> {
        let mapper = match self {
            Self::Apple(_) => super::apple::decode_profile,
            Self::Facebook(_) => super::facebook::graph_profile,
            Self::Cognito(_) => super::super::cognito::decode_profile,
            Self::Microsoft { .. } => super::microsoft::decode_profile,
            Self::Paybin { .. } => super::paybin::decode_profile,
            Self::PayPal => super::paypal::decode_profile,
            Self::Twitch(_) => super::twitch::decode_profile,
            Self::Line { .. } => line_profile,
            Self::Twitter => super::twitter::decode_profile,
            Self::WeChat { .. } => super::wechat::decode_profile,
            _ => {
                return Err(AuthError::internal(
                    "Provider requires native profile construction",
                ));
            }
        };
        mapper(profile).map(Some).map_err(AuthError::internal)
    }
}

pub(in crate::plugins::oauth) fn profile_email(
    profile: &Value,
) -> Result<SchemaValue<Option<String>>, String> {
    profile
        .get("email")
        .cloned()
        .map(serde_json::from_value::<Option<String>>)
        .transpose()
        .map(|value| value.map(SchemaValue::Typed).unwrap_or_default())
        .map_err(|error| format!("Invalid provider email: {error}"))
}

fn line_profile(profile: Value) -> Result<OAuthUserInfo, String> {
    let name = profile
        .get("name")
        .filter(|value| crate::plugins::json_body::is_truthy(value))
        .map(|value| super::decode_profile_name(Some(value)))
        .unwrap_or_else(|| Some(String::new()).into());
    let mut user = openid_profile(profile, "LINE", Some(false).into())?;
    user.name = name;
    Ok(user)
}

fn openid_profile(
    v: Value,
    provider: &str,
    email_verified: SchemaValue<Option<bool>>,
) -> Result<OAuthUserInfo, String> {
    Ok(OAuthUserInfo {
        additional_fields: Default::default(),
        id: v
            .get("sub")
            .and_then(|v| v.as_str())
            .ok_or("missing sub")?
            .to_string(),
        email: profile_email(&v)?,
        name: super::decode_profile_name(v.get("name")),
        image: v
            .get("picture")
            .cloned()
            .map(serde_json::from_value)
            .transpose()
            .map_err(|error| format!("Invalid {provider} picture: {error}"))?,
        email_verified,
    })
}

pub(super) fn prepare_discord_profile(profile: &mut Value) -> Result<(), String> {
    let id = profile
        .get("id")
        .and_then(Value::as_str)
        .ok_or("missing id")?;
    let image = if profile.get("avatar") == Some(&Value::Null) {
        let discriminator = profile
            .get("discriminator")
            .and_then(Value::as_str)
            .ok_or("missing discriminator")?;
        let index = if discriminator == "0" {
            (id.parse::<u64>()
                .map_err(|error| format!("Invalid Discord snowflake: {error}"))?
                >> 22)
                % 6
        } else {
            discriminator
                .parse::<u64>()
                .map_err(|error| format!("Invalid Discord discriminator: {error}"))?
                % 5
        };
        format!("https://cdn.discordapp.com/embed/avatars/{index}.png")
    } else {
        let avatar = profile
            .get("avatar")
            .and_then(Value::as_str)
            .ok_or("missing avatar")?;
        let extension = if avatar.starts_with("a_") {
            "gif"
        } else {
            "png"
        };
        format!("https://cdn.discordapp.com/avatars/{id}/{avatar}.{extension}")
    };
    let _ = profile
        .as_object_mut()
        .ok_or("Discord profile must be an object")?
        .insert("image_url".into(), Value::String(image));
    Ok(())
}

pub(in crate::plugins::oauth) async fn github_profile(
    user_url: &str,
    emails_url: &str,
    request: &OAuthUserInfoRequest,
    mapper: Option<&dyn OAuthProfileMapper>,
) -> AuthResult<Option<ProviderProfile>> {
    let client = reqwest::Client::new();
    let get = |url: &str| {
        Ok::<_, AuthError>(
            client
                .get(url)
                .header(
                    reqwest::header::AUTHORIZATION,
                    super::token_http::authorization(
                        "Bearer",
                        &request.access_token.field_value(),
                    )?,
                )
                .header("Accept", "application/json")
                .header("User-Agent", "better-auth"),
        )
    };
    let profile = super::super::social_profile::fetch_native_profile(get(user_url)?).await?;
    if profile.error.is_truthy() {
        return Ok(None);
    }
    let emails = super::super::social_profile::fetch_native_profile(get(emails_url)?).await?;
    native::github(&profile.data, &emails.data, mapper)
        .await
        .map(Some)
}
