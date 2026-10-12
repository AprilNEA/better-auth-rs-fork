use super::*;
use better_auth_core::field_value::{FieldObject, FieldObjectSource, FieldPropertyDescriptor};

struct UserSource {
    case: &'static str,
    fields: FieldMap,
    state: Arc<Mutex<Observed>>,
    thrown: FieldValue,
}

impl FieldObjectSource for UserSource {
    fn own_keys(&self) -> AuthResult<Vec<String>> {
        Ok(self.fields.keys().cloned().collect())
    }

    fn own_property_descriptor(&self, name: &str) -> AuthResult<Option<FieldPropertyDescriptor>> {
        Ok(self
            .fields
            .contains_key(name)
            .then_some(FieldPropertyDescriptor { enumerable: true }))
    }

    fn get(&self, name: &str) -> AuthResult<Option<FieldValue>> {
        if matches!(name, "id" | "unread") {
            lock(&self.state)?.events.push(format!("user.{name}"));
            if name == "unread"
                || matches!(
                    self.case,
                    "getter-error" | "getter-no-fields" | "getter-email"
                )
            {
                return Err(AuthError::from_thrown(self.thrown.clone()));
            }
        }
        Ok(self.fields.get(name).cloned())
    }

    fn set(&self, _: String, _: FieldValue) -> AuthResult<Option<FieldValue>> {
        Err(AuthError::internal("Injected User must not be mutated"))
    }

    fn delete(&self, _: &str) -> AuthResult<Option<FieldValue>> {
        Err(AuthError::internal("Injected User must not be mutated"))
    }

    fn snapshot_fields(&self) -> AuthResult<FieldMap> {
        self.own_keys()?
            .into_iter()
            .map(|name| {
                let value = self.get(&name)?.unwrap_or_default();
                Ok((name, value))
            })
            .collect()
    }

    fn identity(&self) -> usize {
        std::ptr::from_ref(self).addr()
    }
}

pub(super) fn injected_user(
    case: &'static str,
    shared: &FieldValue,
    state: &Arc<Mutex<Observed>>,
    thrown: &FieldValue,
) -> AuthResult<FieldValue> {
    let user = snapshot_user(case, shared);
    if !case.starts_with("getter-") {
        return Ok(user);
    }
    Ok(FieldObject::from_source(Arc::new(UserSource {
        case,
        fields: user.enumerable_fields()?,
        state: state.clone(),
        thrown: thrown.clone(),
    }))
    .into())
}
