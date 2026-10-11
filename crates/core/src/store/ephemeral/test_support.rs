use crate::{AuthResult, FieldMap, FieldValue, StructuredCloneContext};

/// Compare acyclic fixture trees structurally; identity checks retain the original handles.
pub(super) fn snapshot_tree(value: &FieldValue) -> AuthResult<FieldValue> {
    fn plain_tree(value: &FieldValue) -> AuthResult<FieldValue> {
        Ok(match value {
            FieldValue::Array(values) => values
                .iter()?
                .map(|value| plain_tree(&value?))
                .collect::<AuthResult<Vec<_>>>()?
                .into(),
            FieldValue::Object(object) => object
                .snapshot_fields()?
                .into_iter()
                .map(|(name, value)| Ok((name, plain_tree(&value)?)))
                .collect::<AuthResult<FieldMap>>()?
                .into(),
            value => value.clone(),
        })
    }

    plain_tree(&StructuredCloneContext::new().clone_value(value)?)
}
