use super::{Group, references};
use serde::Deserialize;

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub(crate) struct Fixture {
    version: String,
    backend: String,
    pub(crate) id_field_name: String,
    pub(crate) groups: Vec<Group>,
}

#[expect(
    clippy::panic_in_result_fn,
    reason = "The paired contract must retain both ID strategies and all direct, transaction, and unknown-field observations"
)]
pub(crate) fn load_query_id_state() -> Result<Fixture, Box<dyn std::error::Error + Send + Sync>> {
    let fixture: Fixture = serde_json::from_str(include_str!(
        "../fixtures/device-query-id-state-memory-1.7.6.json"
    ))?;
    assert_eq!(fixture.version, "1.7.6");
    assert_eq!(fixture.backend, "memory");
    assert_eq!(fixture.id_field_name, "old_id");
    assert_eq!(
        fixture
            .groups
            .iter()
            .map(|group| group.serial)
            .collect::<Vec<_>>(),
        [false, true]
    );
    for group in &fixture.groups {
        assert_eq!(
            group
                .cases
                .iter()
                .map(|case| case.name.as_str())
                .collect::<Vec<_>>(),
            [
                "id-alias-direct",
                "id-alias-transaction-commit",
                "unknown-field",
                "unknown-field-transaction-commit",
            ]
        );
        for case in &group.cases {
            references::validate_storage(case)?;
        }
    }
    Ok(fixture)
}
