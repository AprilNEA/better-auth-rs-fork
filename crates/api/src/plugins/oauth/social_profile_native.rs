use better_auth_core::{AuthResult, FieldMap, FieldValue};

use super::super::providers::{OAuthProvider, OAuthUserInfo, OAuthUserInfoResponse};

#[derive(Debug)]
pub(in crate::plugins::oauth) enum LegacySubject {
    Direct(FieldValue),
    ProfileUser(FieldValue),
}

#[derive(Debug)]
pub(in crate::plugins::oauth) struct ProviderProfile {
    pub(in crate::plugins::oauth) value: FieldValue,
    pub(in crate::plugins::oauth) legacy_subject: Option<LegacySubject>,
}

impl Default for ProviderProfile {
    fn default() -> Self {
        Self {
            value: FieldValue::Null,
            legacy_subject: None,
        }
    }
}

impl From<FieldValue> for ProviderProfile {
    fn from(value: FieldValue) -> Self {
        Self {
            value,
            legacy_subject: None,
        }
    }
}

impl ProviderProfile {
    pub(in crate::plugins::oauth) fn from_typed(
        provider: &OAuthProvider,
        response: OAuthUserInfoResponse,
    ) -> AuthResult<Self> {
        Self::from_parts(provider, response.user, response.data.into())
    }

    pub(in crate::plugins::oauth) fn from_parts(
        provider: &OAuthProvider,
        user: OAuthUserInfo,
        data: FieldValue,
    ) -> AuthResult<Self> {
        let legacy_subject = (provider.uses_legacy_profile_subject()
            && provider.account_subject.is_none())
        .then(|| LegacySubject::Direct(user.id.clone().into()));
        let mut user = user.into_native().enumerable_fields()?;
        if !provider.default_profile_includes_id() {
            let _ = user.remove("id");
        }
        Ok(Self {
            value: FieldMap::from([("user".into(), user.into()), ("data".into(), data)]).into(),
            legacy_subject,
        })
    }

    pub(in crate::plugins::oauth) fn replace_user(&mut self, user: FieldMap) -> AuthResult<()> {
        let mut response = self.value.enumerable_fields()?;
        let _ = response.insert("user".into(), user.into());
        self.value = response.into();
        Ok(())
    }

    pub(in crate::plugins::oauth) fn apply_mapped(
        &mut self,
        mapped: &FieldValue,
    ) -> AuthResult<()> {
        let mut user = self.value.model_property("user")?.enumerable_fields()?;
        user.extend(mapped.enumerable_fields()?);
        self.replace_user(user)
    }

    pub(in crate::plugins::oauth) async fn map_user(
        mut self,
        provider: &OAuthProvider,
    ) -> AuthResult<Self> {
        if let Some(mapper) = &provider.map_profile_to_user {
            let mapped = mapper
                .map_profile_native(&self.value.model_property("data")?)
                .await?;
            self.apply_mapped(&mapped)?;
        }
        Ok(self)
    }
}
