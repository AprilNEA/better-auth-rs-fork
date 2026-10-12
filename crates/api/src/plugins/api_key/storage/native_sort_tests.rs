use super::*;
use crate::plugins::test_helpers::native_sort_contract::{Harness, assert_case, cases};

#[test]
fn api_key_native_sort_replays_complete_source_runtime() -> AuthResult<()> {
    for case in cases("api-key") {
        let harness = Harness::new(case)?;
        let before = harness.before()?;
        let mut keys = harness.rows();
        let result = sort_keys(&mut keys, "name", case["direction"].as_str())
            .map(|()| FieldValue::from(keys));
        assert_case(&harness.finish(before, result)?, case);
    }
    Ok(())
}
