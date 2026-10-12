//! Envelope selection retains native values, callback order, and the full source used by provider literals.

use better_auth_core::{AuthError, AuthResult, FieldValue, observability::LogArgument};

use super::{ProviderKind, index_zero, optional_property};

impl ProviderKind {
    pub(in crate::plugins::oauth) fn http_profile_data(
        &self,
        response: &FieldValue,
        error: &FieldValue,
    ) -> AuthResult<Option<FieldValue>> {
        if matches!(self, Self::Cloudflare) {
            if error.is_truthy()
                || !optional_property(response, "success")?.is_truthy()
                || !response.model_property("result")?.is_truthy()
            {
                let diagnostic = if error.is_null() || error.is_undefined() {
                    optional_property(response, "errors")?
                } else {
                    error.clone()
                };
                better_auth_core::observability::logger::current().error(
                    "Failed to fetch user info from Cloudflare:",
                    &[LogArgument::Native(&diagnostic)],
                )?;
                return Ok(None);
            }
            return response.model_property("result").map(Some);
        }
        if error.is_truthy() {
            return Ok(None);
        }
        match self {
            Self::Discord => {
                // Discord's numeric avatar preprocessing still consumes its legacy JSON shape.
                let mut profile = response
                    .json()?
                    .ok_or_else(|| AuthError::internal("Legacy Discord profile is undefined"))?;
                super::super::prepare_discord_profile(&mut profile).map_err(AuthError::internal)?;
                Ok(Some(profile.into()))
            }
            Self::Kick => index_zero(&response.model_property("data")?).map(Some),
            Self::Linear => {
                if !optional_property(&optional_property(response, "data")?, "viewer")?.is_truthy()
                {
                    return Ok(None);
                }
                response
                    .model_property("data")?
                    .model_property("viewer")
                    .map(Some)
            }
            Self::Notion => {
                if !response.is_truthy() {
                    return Ok(None);
                }
                let profile = optional_property(
                    &optional_property(&response.model_property("bot")?, "owner")?,
                    "user",
                )?;
                Ok(profile.is_truthy().then_some(profile))
            }
            _ => Ok(Some(response.clone())),
        }
    }
}
