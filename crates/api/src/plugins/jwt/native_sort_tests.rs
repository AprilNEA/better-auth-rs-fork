use super::*;
use crate::plugins::test_helpers::native_sort_contract::{Harness, assert_jwk_selection, cases};
use better_auth_core::{AuthRecordFields, FromFieldMap};

#[test]
fn jwk_native_sort_replays_selection_runtime_and_native_value_identity() -> AuthResult<()> {
    for case in cases("jwk") {
        let harness = Harness::new(case)?;
        let before = harness.before()?;
        let rows = harness
            .rows()
            .into_iter()
            .map(|row| better_auth_core::Jwk::from_field_values(row.enumerable_fields()?))
            .collect::<AuthResult<_>>()?;
        let result = keys::latest(rows, case["algorithm"].as_str(), "EdDSA")
            .and_then(|key| {
                key.map(|key| key.field_values().map(FieldValue::from))
                    .transpose()
            })
            .map(Option::unwrap_or_default);
        assert_jwk_selection(&harness.finish(before, result)?, case);
    }
    Ok(())
}
