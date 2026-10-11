//! Typed profile constructors transfer authority to one native provider response.

use super::{OAuthUserInfo, OAuthUserInfoResponse};
use crate::plugins::oauth::generic::OAuthProfile;
use better_auth_core::{FieldMap, FieldValue, SchemaField, SchemaValue};

fn present<T: SchemaField>(value: SchemaValue<T>) -> Option<FieldValue> {
    (!value.is_undefined()).then(|| value.into_field_value())
}

impl OAuthUserInfo {
    /// Consume the typed user without discarding native extension values or explicit undefined.
    /// Present named fields override extensions; missing named fields preserve extensions.
    pub fn into_native(self) -> FieldValue {
        let order = ["id", "name", "email", "image", "emailVerified"].map(str::to_owned);
        self.additional_fields
            .with_schema_fields(
                &order,
                [
                    ("id", Some(self.id.into())),
                    ("name", present(self.name)),
                    ("email", present(self.email)),
                    (
                        "image",
                        self.image
                            .map(|image| image.map_or(FieldValue::Null, FieldValue::from)),
                    ),
                    ("emailVerified", present(self.email_verified)),
                ],
            )
            .into()
    }
}

impl OAuthUserInfoResponse {
    /// Consume the typed provider response at the JSON callback boundary.
    /// Later profile reads must use the returned value as their only record.
    pub fn into_native(self) -> FieldValue {
        FieldMap::from([
            ("user".into(), self.user.into_native()),
            ("data".into(), self.data.into()),
        ])
        .into()
    }
}

impl OAuthProfile {
    /// Consume a typed mapper patch without serializing its native extension fields.
    /// An outer `Some` supplies the named property, including a supplied undefined value.
    pub fn into_native(self) -> FieldValue {
        self.additional_fields
            .with_schema_fields(
                &[],
                [
                    ("email", self.email.map(SchemaValue::into_field_value)),
                    ("name", self.name.map(SchemaValue::into_field_value)),
                    (
                        "image",
                        self.image
                            .map(|image| image.map_or(FieldValue::Null, FieldValue::from)),
                    ),
                    (
                        "emailVerified",
                        self.email_verified.map(SchemaValue::into_field_value),
                    ),
                ],
            )
            .into()
    }
}
