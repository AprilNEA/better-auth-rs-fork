use better_auth_core::{AuthResult, FieldMap, FieldValue};

pub(super) fn lowercase(value: &FieldValue, expression: &str) -> AuthResult<FieldValue> {
    value.lowercase_method(expression)
}

pub(super) fn lower_email(user: &FieldValue) -> AuthResult<FieldValue> {
    lowercase(&user.model_property("email")?, "userInfo.email")
}

pub(super) fn callback_user(user: &FieldValue, account_id: FieldValue) -> AuthResult<FieldValue> {
    let mut fields = user.enumerable_fields()?;
    let _ = fields.insert("id".into(), account_id);
    let _ = fields.insert("email".into(), user.model_property("email")?);
    let name = user.model_property("name")?;
    let _ = fields.insert(
        "name".into(),
        if name.is_truthy() { name } else { "".into() },
    );
    Ok(fields.into())
}

pub(super) fn direct_user(info: &FieldValue, account_id: FieldValue) -> AuthResult<FieldValue> {
    let mut fields = info.model_property("user")?.enumerable_fields()?;
    let _ = fields.insert(
        "email".into(),
        info.model_property("user")?.model_property("email")?,
    );
    let _ = fields.insert("id".into(), account_id);
    let name = info.model_property("user")?.model_property("name")?;
    let _ = fields.insert(
        "name".into(),
        if name.is_truthy() { name } else { "".into() },
    );
    let _ = fields.insert(
        "image".into(),
        info.model_property("user")?.model_property("image")?,
    );
    let verified = info
        .model_property("user")?
        .model_property("emailVerified")?;
    let _ = fields.insert(
        "emailVerified".into(),
        if verified.is_truthy() {
            verified
        } else {
            false.into()
        },
    );
    Ok(fields.into())
}

pub(super) fn profile_fields(
    user: &FieldValue,
    omit_id: bool,
) -> AuthResult<(FieldValue, FieldValue, FieldMap)> {
    if omit_id {
        let _ = user.model_property("id")?;
    }
    let _ = user.model_property("email")?;
    let _ = user.model_property("emailVerified")?;
    let name = user.model_property("name")?;
    let image = user.model_property("image")?;
    let excluded = if omit_id {
        &["id", "email", "emailVerified", "name", "image"][..]
    } else {
        &["email", "emailVerified", "name", "image"][..]
    };
    Ok((name, image, user.enumerable_fields_except(excluded)?))
}
