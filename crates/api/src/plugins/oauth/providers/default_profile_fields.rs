//! Native provider literals preserve upstream field order and repeated property reads.

use better_auth_core::{AuthResult, FieldMap, FieldValue, Utf16String};

use super::{
    coalesce, index_zero, literal, name_coalesce, name_or, optional_property, or, placeholder,
};

pub(super) fn discord(profile: &FieldValue) -> AuthResult<FieldMap> {
    Ok(literal([
        ("name", name_or(profile, "global_name", "username")?),
        ("email", profile.model_property("email")?),
        ("emailVerified", profile.model_property("verified")?),
        ("image", profile.model_property("image_url")?),
    ]))
}

pub(super) fn gitlab(profile: &FieldValue) -> AuthResult<FieldMap> {
    Ok(literal([
        ("name", name_coalesce(profile, "name", "username")?),
        ("email", profile.model_property("email")?),
        ("image", profile.model_property("avatar_url")?),
        (
            "emailVerified",
            coalesce(profile.model_property("email_verified")?, || {
                Ok(false.into())
            })?,
        ),
    ]))
}

pub(super) fn spotify(profile: &FieldValue) -> AuthResult<FieldMap> {
    Ok(literal([
        ("name", profile.model_property("display_name")?),
        ("email", profile.model_property("email")?),
        (
            "image",
            optional_property(&index_zero(&profile.model_property("images")?)?, "url")?,
        ),
        ("emailVerified", false.into()),
    ]))
}

pub(super) fn huggingface(profile: &FieldValue) -> AuthResult<FieldMap> {
    Ok(literal([
        ("name", name_or(profile, "name", "preferred_username")?),
        ("email", profile.model_property("email")?),
        ("image", profile.model_property("picture")?),
        (
            "emailVerified",
            coalesce(profile.model_property("email_verified")?, || {
                Ok(false.into())
            })?,
        ),
    ]))
}

pub(super) fn polar(profile: &FieldValue) -> AuthResult<FieldMap> {
    Ok(literal([
        ("name", name_or(profile, "public_name", "username")?),
        ("email", profile.model_property("email")?),
        ("image", profile.model_property("avatar_url")?),
        (
            "emailVerified",
            coalesce(profile.model_property("email_verified")?, || {
                Ok(false.into())
            })?,
        ),
    ]))
}

pub(super) fn unverified_openid(profile: &FieldValue) -> AuthResult<FieldMap> {
    Ok(literal([
        ("name", profile.model_property("name")?),
        ("email", profile.model_property("email")?),
        ("image", profile.model_property("picture")?),
        ("emailVerified", false.into()),
    ]))
}

pub(super) fn roblox(profile: &FieldValue) -> AuthResult<FieldMap> {
    Ok(literal([
        ("name", name_or(profile, "nickname", "preferred_username")?),
        ("image", profile.model_property("picture")?),
        (
            "email",
            placeholder(profile.model_property("sub")?, "roblox")?,
        ),
        ("emailVerified", false.into()),
    ]))
}

pub(super) fn notion(profile: &FieldValue) -> AuthResult<FieldMap> {
    Ok(literal([
        (
            "name",
            or(profile.model_property("name")?, || Ok("".into()))?,
        ),
        (
            "email",
            or(
                optional_property(&profile.model_property("person")?, "email")?,
                || Ok(FieldValue::Null),
            )?,
        ),
        ("image", profile.model_property("avatar_url")?),
        ("emailVerified", false.into()),
    ]))
}

pub(super) fn vercel(profile: &FieldValue) -> AuthResult<FieldMap> {
    Ok(literal([
        (
            "name",
            name_coalesce(profile, "name", "preferred_username")?,
        ),
        ("email", profile.model_property("email")?),
        ("image", profile.model_property("picture")?),
        (
            "emailVerified",
            coalesce(profile.model_property("email_verified")?, || {
                Ok(false.into())
            })?,
        ),
    ]))
}

pub(super) fn figma(profile: &FieldValue) -> AuthResult<FieldMap> {
    Ok(literal([
        ("name", profile.model_property("handle")?),
        ("email", profile.model_property("email")?),
        ("image", profile.model_property("img_url")?),
        ("emailVerified", false.into()),
    ]))
}

pub(super) fn dropbox(profile: &FieldValue) -> AuthResult<FieldMap> {
    Ok(literal([
        (
            "name",
            optional_property(&profile.model_property("name")?, "display_name")?,
        ),
        ("email", profile.model_property("email")?),
        (
            "emailVerified",
            or(profile.model_property("email_verified")?, || {
                Ok(false.into())
            })?,
        ),
        ("image", profile.model_property("profile_photo_url")?),
    ]))
}

pub(super) fn kick(profile: &FieldValue) -> AuthResult<FieldMap> {
    Ok(literal([
        ("name", profile.model_property("name")?),
        ("email", profile.model_property("email")?),
        ("image", profile.model_property("profile_picture")?),
        ("emailVerified", false.into()),
    ]))
}

pub(super) fn linkedin(profile: &FieldValue) -> AuthResult<FieldMap> {
    Ok(literal([
        ("name", profile.model_property("name")?),
        ("email", profile.model_property("email")?),
        (
            "emailVerified",
            coalesce(profile.model_property("email_verified")?, || {
                Ok(false.into())
            })?,
        ),
        ("image", profile.model_property("picture")?),
    ]))
}

pub(super) fn slack(profile: &FieldValue) -> AuthResult<FieldMap> {
    Ok(literal([
        (
            "name",
            or(profile.model_property("name")?, || Ok("".into()))?,
        ),
        ("email", profile.model_property("email")?),
        ("emailVerified", profile.model_property("email_verified")?),
        (
            "image",
            or(profile.model_property("picture")?, || {
                profile.model_property("https://slack.com/user_image_512")
            })?,
        ),
    ]))
}

pub(super) fn naver(profile: &FieldValue) -> AuthResult<FieldMap> {
    let res = or(profile.model_property("response")?, || {
        Ok(FieldMap::new().into())
    })?;
    Ok(literal([
        ("name", name_or(&res, "name", "nickname")?),
        ("email", res.model_property("email")?),
        ("image", res.model_property("profile_image")?),
        ("emailVerified", false.into()),
    ]))
}

pub(super) fn linear(profile: &FieldValue) -> AuthResult<FieldMap> {
    Ok(literal([
        ("name", profile.model_property("name")?),
        ("email", profile.model_property("email")?),
        ("image", profile.model_property("avatarUrl")?),
        ("emailVerified", false.into()),
    ]))
}

pub(super) fn kakao(profile: &FieldValue) -> AuthResult<FieldMap> {
    let account = or(profile.model_property("kakao_account")?, || {
        Ok(FieldMap::new().into())
    })?;
    let profile = or(account.model_property("profile")?, || {
        Ok(FieldMap::new().into())
    })?;
    Ok(literal([
        (
            "name",
            or(profile.model_property("nickname")?, || {
                or(account.model_property("name")?, || Ok("".into()))
            })?,
        ),
        ("email", account.model_property("email")?),
        (
            "image",
            or(profile.model_property("profile_image_url")?, || {
                profile.model_property("thumbnail_image_url")
            })?,
        ),
        (
            "emailVerified",
            (account.model_property("is_email_valid")?.is_truthy()
                && account.model_property("is_email_verified")?.is_truthy())
            .into(),
        ),
    ]))
}

pub(super) fn zoom(profile: &FieldValue) -> AuthResult<FieldMap> {
    Ok(literal([
        ("name", profile.model_property("display_name")?),
        ("image", profile.model_property("pic_url")?),
        ("email", profile.model_property("email")?),
        (
            "emailVerified",
            profile.model_property("verified")?.is_truthy().into(),
        ),
    ]))
}

pub(super) fn salesforce(profile: &FieldValue) -> AuthResult<FieldMap> {
    Ok(literal([
        ("name", profile.model_property("name")?),
        ("email", profile.model_property("email")?),
        (
            "image",
            or(
                optional_property(&profile.model_property("photos")?, "picture")?,
                || optional_property(&profile.model_property("photos")?, "thumbnail"),
            )?,
        ),
        (
            "emailVerified",
            coalesce(profile.model_property("email_verified")?, || {
                Ok(false.into())
            })?,
        ),
    ]))
}

pub(super) fn vk(profile: &FieldValue) -> AuthResult<FieldMap> {
    let mut user = literal([
        (
            "first_name",
            profile
                .model_property("user")?
                .model_property("first_name")?,
        ),
        (
            "last_name",
            profile
                .model_property("user")?
                .model_property("last_name")?,
        ),
        (
            "email",
            profile.model_property("user")?.model_property("email")?,
        ),
        (
            "image",
            profile.model_property("user")?.model_property("avatar")?,
        ),
        ("emailVerified", false.into()),
        (
            "birthday",
            profile.model_property("user")?.model_property("birthday")?,
        ),
        (
            "sex",
            profile.model_property("user")?.model_property("sex")?,
        ),
    ]);
    let mut name = profile
        .model_property("user")?
        .model_property("first_name")?
        .display_utf16()?
        .as_utf16()
        .to_vec();
    name.push(u16::from(b' '));
    name.extend_from_slice(
        profile
            .model_property("user")?
            .model_property("last_name")?
            .display_utf16()?
            .as_utf16(),
    );
    let _ = user.insert("name".into(), Utf16String::from_units(name).into());
    Ok(user)
}

pub(super) fn tiktok(profile: &FieldValue) -> AuthResult<FieldMap> {
    let user = || profile.model_property("data")?.model_property("user");
    Ok(literal([
        (
            "email",
            or(user()?.model_property("email")?, || {
                placeholder(user()?.model_property("open_id")?, "tiktok")
            })?,
        ),
        (
            "name",
            or(user()?.model_property("display_name")?, || {
                or(user()?.model_property("username")?, || Ok("".into()))
            })?,
        ),
        ("image", user()?.model_property("avatar_large_url")?),
        ("emailVerified", false.into()),
    ]))
}
