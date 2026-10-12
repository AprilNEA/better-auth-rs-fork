use super::*;
use crate::plugins::api_key::{ApiKeyGenerator, ApiKeyPlugin, CreateKeyRequest};
use better_auth_core::{
    AuthConfig, AuthPlugin, AuthSchema,
    id::{IdGeneration, IdGenerator},
    plugin_runtime::ModelFields,
    store::{EphemeralStore, StatelessSchema, schema::EntityRole},
    user_fields::{
        FieldTransforms, UserConfig, UserFieldConfig, UserFieldTransform, UserFieldType,
    },
};

type Events = Arc<Mutex<Vec<(&'static str, &'static str, FieldValue)>>>;

struct Fields(Events);

#[async_trait]
impl<S: AuthSchema> AuthPlugin<S> for Fields {
    fn name(&self) -> &'static str {
        "api-key-create-date-identity"
    }

    fn routes(&self) -> Vec<better_auth_core::AuthRoute> {
        Vec::new()
    }

    async fn on_request(
        &self,
        _: &better_auth_core::AuthRequest,
        _: &AuthContext<S>,
    ) -> AuthResult<Option<better_auth_core::AuthResponse>> {
        Ok(None)
    }

    fn schema(&self, fields: &mut ModelFields) -> AuthResult<()> {
        fields.register_model_fields(
            EntityRole::ApiKey,
            UserConfig {
                additional_fields: Some(
                    ["createdAt", "updatedAt"]
                        .into_iter()
                        .map(|name| {
                            let input = self.0.clone();
                            let output = self.0.clone();
                            (
                                name.into(),
                                UserFieldConfig {
                                    field_type: UserFieldType::Date,
                                    required: Some(true),
                                    transform: Some(FieldTransforms {
                                        input: Some(UserFieldTransform::new(move |value| {
                                            assert!(matches!(value, FieldValue::Date(_)));
                                            if name == "createdAt" {
                                                value.set_model_property(
                                                    "createdOnly",
                                                    "marker".into(),
                                                )?;
                                            } else {
                                                assert!(
                                                    value
                                                        .model_property("createdOnly")?
                                                        .is_undefined()
                                                );
                                            }
                                            input.lock().unwrap().push((
                                                name,
                                                "input",
                                                value.clone(),
                                            ));
                                            Ok(value)
                                        })),
                                        output: Some(UserFieldTransform::new(move |value| {
                                            output.lock().unwrap().push((
                                                name,
                                                "output",
                                                value.clone(),
                                            ));
                                            Ok(value)
                                        })),
                                    }),
                                    ..Default::default()
                                },
                            )
                        })
                        .collect(),
                ),
            },
        )
    }
}

struct Generator;

#[async_trait]
impl ApiKeyGenerator for Generator {
    async fn generate(&self, _: usize, _: Option<&str>) -> AuthResult<String> {
        Ok("x".repeat(64))
    }
}

#[tokio::test]
async fn creation_keeps_date_objects_separate_through_adapter_and_cache_boundaries()
-> AuthResult<()> {
    for mode in ["database", "secondary", "fallback"] {
        let events = Events::default();
        let fields = Fields(events.clone());
        let cache = Arc::new(Storage {
            entries: Mutex::new(Vec::new()),
            observer: Observer::default(),
        });
        let key_config = ApiKeyConfig {
            storage: if mode == "database" {
                ApiKeyStorage::Database
            } else {
                ApiKeyStorage::SecondaryStorage
            },
            fallback_to_database: mode == "fallback",
            custom_storage: Some(cache.clone()),
            custom_key_generator: Some(Arc::new(Generator)),
            disable_key_hashing: true,
            ..Default::default()
        };
        let plugin = ApiKeyPlugin::with_config(key_config);
        let mut config = AuthConfig::new("date-identity-secret-at-least-32-characters");
        config.advanced.database.generate_id = Some(IdGeneration::Custom(IdGenerator::new(|_| {
            Ok(Some("date-key".into()))
        })));
        let config = Arc::new(config);
        let raw = Arc::new(EphemeralStore::new(config.clone()));
        let context: AuthContext<StatelessSchema> =
            crate::plugins::test_helpers::initialize_test_context(
                config,
                raw.clone(),
                &[&plugin, &fields],
            )
            .await?;
        let started = Utc::now().timestamp_millis() as f64;
        let response = plugin
            .create_key(
                &context,
                &CreateKeyRequest {
                    user_id: Some("owner".into()),
                    name: Some("Date key".into()),
                    rate_limit_enabled: Some(false),
                    rate_limit_time_window: Some(60_000.0),
                    rate_limit_max: Some(3.0),
                    ..Default::default()
                },
            )
            .await?
            .into_field_value()?;
        let ended = Utc::now().timestamp_millis() as f64;
        let created = response.model_property("createdAt")?;
        let updated = response.model_property("updatedAt")?;
        assert!(!created.strict_equals(&updated));
        for date in [&created, &updated] {
            let FieldValue::Date(date) = date else {
                return Err(AuthError::internal(
                    "Create response must retain native Dates",
                ));
            };
            assert!((started..=ended).contains(&date.milliseconds()));
        }
        assert!(updated.model_property("createdOnly")?.is_undefined());
        let mut expected = FieldValue::from_json(json!({
            "id":"date-key", "configId":"default", "name":"Date key", "prefix":null,
            "start":"xxxxxx", "key":"x".repeat(64), "enabled":true, "expiresAt":null,
            "referenceId":"owner", "lastRefillAt":null, "lastRequest":null, "metadata":null,
            "rateLimitMax":3, "rateLimitTimeWindow":60000, "remaining":null,
            "refillAmount":null, "refillInterval":null, "rateLimitEnabled":false,
            "requestCount":0, "permissions":null,
        }))?
        .enumerable_fields()?;
        expected.extend([
            ("createdAt".into(), created.clone()),
            ("updatedAt".into(), updated.clone()),
        ]);
        assert_eq!(response.enumerable_fields()?, expected);
        let rows = raw.storage_rows(EntityRole::ApiKey)?;
        if mode == "secondary" {
            assert!(events.lock().unwrap().is_empty());
            assert!(rows.is_empty());
            assert!(created.model_property("createdOnly")?.is_undefined());
        } else {
            let events = events.lock().unwrap();
            assert_eq!(
                events
                    .iter()
                    .map(|(field, phase, _)| (*field, *phase))
                    .collect::<Vec<_>>(),
                [
                    ("createdAt", "input"),
                    ("updatedAt", "input"),
                    ("createdAt", "output"),
                    ("updatedAt", "output"),
                ]
            );
            for (name, _, value) in events.iter() {
                assert!(value.strict_equals(if *name == "createdAt" {
                    &created
                } else {
                    &updated
                }));
            }
            assert_eq!(created.model_property("createdOnly")?, "marker".into());
            let mut stored = expected.clone();
            let _ = stored.remove("permissions");
            let _ = stored.insert("metadata".into(), "null".into());
            assert_eq!(rows, [stored]);
        }
        for role in [
            EntityRole::User,
            EntityRole::Session,
            EntityRole::Account,
            EntityRole::Verification,
        ] {
            assert!(raw.storage_rows(role)?.is_empty());
        }
        let entries = cache.entries.lock().unwrap();
        if mode == "database" {
            assert!(entries.is_empty());
        } else {
            let by_id = entries
                .iter()
                .find(|(key, _)| key == &FieldValue::from("api-key:by-id:date-key"))
                .unwrap()
                .1
                .clone();
            let stored = better_auth_core::utils::json::parse_native_json(&by_id)?;
            let mut expected = expected.clone();
            let _ = expected.remove("permissions");
            assert_eq!(stored.json()?, FieldValue::from(expected).json()?);
            let by_hash = entries
                .iter()
                .find(|(key, _)| key == &FieldValue::from(format!("api-key:{}", "x".repeat(64))))
                .unwrap()
                .1
                .clone();
            assert_eq!(by_id, by_hash);
            assert_eq!(entries.len(), if mode == "fallback" { 2 } else { 3 });
            let index = entries
                .iter()
                .find(|(key, _)| key == &FieldValue::from("api-key:by-ref:owner"));
            if mode == "secondary" {
                assert_eq!(index.unwrap().1, "[\"date-key\"]".into());
            } else {
                assert!(index.is_none());
            }
        }
    }
    Ok(())
}
