use super::*;
use better_auth::__private_core::store::{EphemeralStore, MemoryCacheAdapter};
use serde_json::json;

#[tokio::test]
async fn storage_context_matches_real_initialization() -> AuthResult<()> {
    let fixture: Value = serde_json::from_str(include_str!(
        "../fixtures/telemetry-storage-init-1.7.6.json"
    ))?;
    for database in [false, true] {
        for secondary in [false, true] {
            let (config, reports) = configuration();
            let mut builder = if database {
                BetterAuth::new(config.clone()).store(EphemeralStore::new(Arc::new(config)))
            } else {
                BetterAuth::stateless(config)
            };
            if secondary {
                builder = builder.secondary_storage(Arc::new(MemoryCacheAdapter::new()));
            }
            let auth = builder.build().await?;
            assert_eq!(auth.store().adapter_id(), "memory");
            let config = reports.config()?;
            assert!(auth.store().rate_limit_model_declaration().is_none());
            assert!(
                config
                    .get("rateLimit")
                    .ok_or_else(|| AuthError::internal("Missing rate-limit telemetry"))?
                    .get("modelName")
                    .is_none()
            );
            let case = format!(
                "{}-{}",
                if database { "database" } else { "stateless" },
                if secondary { "secondary" } else { "primary" }
            );
            assert_eq!(
                json!({
                    "database": config.get("database"),
                    "adapter": config.get("adapter"),
                    "secondaryStorage": config.get("secondaryStorage"),
                }),
                *fixture
                    .get(&case)
                    .ok_or_else(|| AuthError::internal(format!("Missing fixture case {case}")))?,
            );
        }
    }
    Ok(())
}

#[cfg(feature = "seaorm2")]
#[tokio::test]
async fn sql_storage_reports_its_adapter_without_querying_a_schema() -> AuthResult<()> {
    use better_auth_seaorm::{
        SeaOrmStore, sea_orm::Database,
        store::__private_test_support::bundled_schema::BundledSchema,
    };

    for secondary in [false, true] {
        let (config, reports) = configuration();
        let database = Database::connect("sqlite::memory:")
            .await
            .map_err(|error| AuthError::internal(error.to_string()))?;
        let mut builder = BetterAuth::new(config.clone())
            .store(SeaOrmStore::<BundledSchema>::new(config, database));
        if secondary {
            builder = builder.secondary_storage(Arc::new(MemoryCacheAdapter::new()));
        }
        let auth = builder.build().await?;
        let config = reports.config()?;
        assert_eq!(config.get("database"), Some(&json!("adapter")));
        assert_eq!(config.get("adapter"), Some(&json!("seaorm")));
        assert_eq!(config.get("secondaryStorage"), Some(&json!(secondary)));
        assert_eq!(auth.store().adapter_id(), "seaorm");
    }
    Ok(())
}

#[tokio::test]
async fn direct_rate_limit_options_preserve_the_captured_telemetry_projection() -> AuthResult<()> {
    let fixture: Value = serde_json::from_str(include_str!(
        "../fixtures/telemetry-rate-limit-model-1.7.6.json"
    ))?;
    let cases = fixture
        .as_object()
        .ok_or_else(|| AuthError::internal("Expected RateLimit telemetry cases"))?;
    for (name, case) in cases {
        let (config, reports) = configuration();
        let options = case
            .get("options")
            .and_then(|options| options.get("rateLimit"));
        let rate_limit = RateLimitConfig {
            storage: Some(RateLimitStorageKind::Database),
            model_name: options
                .and_then(|options| options.get("modelName"))
                .and_then(Value::as_str)
                .map(str::to_owned),
            fields: options
                .and_then(|options| options.get("fields"))
                .cloned()
                .map(serde_json::from_value)
                .transpose()?,
            ..Default::default()
        };
        let _auth = BetterAuth::new(config.clone())
            .store(EphemeralStore::new(Arc::new(config)))
            .rate_limit(rate_limit)
            .build()
            .await?;
        let observed = reports.config()?;
        assert_eq!(
            observed.get("rateLimit"),
            case.get("expected"),
            "{name}: complete RateLimit telemetry"
        );
    }
    Ok(())
}
