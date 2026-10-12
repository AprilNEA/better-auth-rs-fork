use better_auth_core::store::database_hooks::{
    DatabaseHookContext, DatabaseHookUpdate, DatabaseHooks,
};
use better_auth_core::{AuthResult, AuthSchema, FieldMap, FieldValue};

pub(super) struct PhoneNumberHooks;

#[better_auth_core::database_hooks("plugin:phone-number")]
impl<S: AuthSchema> DatabaseHooks<S> for PhoneNumberHooks {
    async fn before_update_user(
        &self,
        user: &mut FieldMap,
        _: &DatabaseHookContext<'_, S>,
    ) -> AuthResult<DatabaseHookUpdate<FieldMap>> {
        if user.get("phoneNumber").is_some_and(FieldValue::is_null) {
            let mut patch = user.clone();
            let _ = patch.insert("phoneNumberVerified".into(), false.into());
            Ok(DatabaseHookUpdate::Patch(patch))
        } else {
            Ok(DatabaseHookUpdate::Continue)
        }
    }
}
