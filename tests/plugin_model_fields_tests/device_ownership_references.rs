use super::*;

const CASES: [(&str, &str, &str, &str); 8] = [
    (
        "tenantKey-match",
        "direct",
        "tenantKey",
        "owner@device-ownership.test",
    ),
    (
        "tenantKey-match",
        "transaction",
        "tenantKey",
        "owner@device-ownership.test",
    ),
    (
        "tenantKey-mismatch",
        "direct",
        "tenantKey",
        "foreign@device-ownership.test",
    ),
    (
        "tenantKey-mismatch",
        "transaction",
        "tenantKey",
        "foreign@device-ownership.test",
    ),
    (
        "stored_tenant-match",
        "direct",
        "stored_tenant",
        "owner@device-ownership.test",
    ),
    (
        "stored_tenant-match",
        "transaction",
        "stored_tenant",
        "owner@device-ownership.test",
    ),
    (
        "stored_tenant-mismatch",
        "direct",
        "stored_tenant",
        "foreign@device-ownership.test",
    ),
    (
        "stored_tenant-mismatch",
        "transaction",
        "stored_tenant",
        "foreign@device-ownership.test",
    ),
];

#[tokio::test]
async fn memory_non_id_reference_redemption_matches_upstream() -> AuthResult<()> {
    for case in CASES {
        contract(memory(), "memory", case, Some("email")).await?;
    }
    Ok(())
}

#[tokio::test]
async fn sqlite_non_id_reference_redemption_matches_upstream() -> AuthResult<()> {
    for case in CASES {
        let (store, _) = device_fixture::sqlite(config()).await;
        contract(Arc::new(store), "sqlite", case, Some("email")).await?;
    }
    Ok(())
}
