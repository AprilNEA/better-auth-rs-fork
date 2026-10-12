#![expect(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::panic_in_result_fn,
    reason = "Pinned backup-code contracts must fail immediately on invalid fixture shapes or native method observations."
)]

use super::*;
use crate::plugins::test_helpers::verification_consumer_native::{
    Harness, NOW, ReplayFailures, SECRET, assert_replay, date, object::Root,
};
use better_auth_core::{
    AuthPlugin, FieldFunction, NativeRequest,
    store::{AuthStore, StatelessSchema, schema::EntityRole},
};
use serde_json::{Value as Json, json};
use std::sync::{OnceLock, Weak};

const IDENTIFIER: &str = "2fa-backup-native";
const CIPHERTEXT: &str = "native-backup-ciphertext";

fn factor() -> FieldMap {
    FieldMap::from([
        ("id".into(), "factor-row".into()),
        ("secret".into(), "native-factor-secret".into()),
        ("backupCodes".into(), CIPHERTEXT.into()),
        ("userId".into(), "owner".into()),
        ("verified".into(), true.into()),
        ("failedVerificationCount".into(), 2.into()),
        ("lockedUntil".into(), FieldValue::Null),
    ])
}

fn owner(owner: &Weak<OnceLock<FieldValue>>) -> FieldValue {
    owner.upgrade().unwrap().get().unwrap().clone()
}

fn visit(visits: &FieldValue, name: String) -> AuthResult<()> {
    let index = visits.as_array().unwrap().len()?;
    visits.set_model_property(&index.to_string(), name.into())
}

fn method(
    object: &Root,
    name: &'static str,
    harness: &Arc<Harness>,
    visits: &FieldValue,
    body: impl Fn(&[FieldValue]) -> AuthResult<FieldValue> + Send + Sync + 'static,
) {
    let expected = object.owner();
    let harness = harness.clone();
    let visits = visits.clone();
    let body = Arc::new(body);
    object.getter(name, false, move |receiver| {
        visit(&visits, format!("{name}:get"))?;
        harness.record(
            &format!("get:{name}"),
            [(
                "sameReceiver".into(),
                receiver.strict_equals(&owner(&expected)).into(),
            )],
        );
        if harness.scenario["fail"] == format!("{name}:get") {
            return harness.fail(&format!("throw:{name}:get"));
        }
        let expected = expected.clone();
        let harness = harness.clone();
        let visits = visits.clone();
        let body = body.clone();
        Ok(FieldFunction::contextual(move |receiver, arguments| {
            visit(&visits, format!("{name}:call"))?;
            harness.record(
                &format!("call:{name}"),
                [
                    (
                        "sameReceiver".into(),
                        receiver.strict_equals(&owner(&expected)).into(),
                    ),
                    (
                        "arguments".into(),
                        harness.observe(&arguments.to_vec().into())?,
                    ),
                ],
            );
            assert!(receiver.strict_equals(&owner(&expected)));
            assert_eq!(arguments.len(), 1);
            if harness.scenario["fail"] == format!("{name}:call") {
                return harness.fail(&format!("throw:{name}:call"));
            }
            body(arguments)
        })
        .into())
    });
}

struct Methods {
    codes: Root,
    visits: FieldValue,
    status: FieldValue,
    updated: FieldValue,
    _updated_root: Option<Root>,
}

impl Methods {
    fn new(harness: &Arc<Harness>) -> AuthResult<Self> {
        let codes = Root::new("date");
        let visits: FieldValue = Vec::<FieldValue>::new().into();
        codes.data("marker", "native-codes".into());
        codes.data("visits", visits.clone());
        let status: FieldValue = match harness.scenario["status"].as_str().unwrap() {
            "false" => false.into(),
            "object" => FieldMap::from([("marker".into(), "native-status".into())]).into(),
            "true" => true.into(),
            value => {
                return Err(AuthError::internal(format!(
                    "Unknown backup status: {value}"
                )));
            }
        };
        let updated_kind = harness.scenario["updated"].as_str().unwrap();
        let updated_root = updated_kind.starts_with("object").then(|| {
            let root = Root::new("object");
            root.data("marker", "native-filter-result".into());
            root.data("ownUndefined", FieldValue::Undefined);
            let json_undefined = updated_kind == "object-undefined";
            method(&root, "toJSON", harness, &visits, move |arguments| {
                assert_eq!(arguments, &[FieldValue::from("")]);
                if json_undefined {
                    return Ok(FieldValue::Undefined);
                }
                Ok(FieldMap::from([
                    ("codes".into(), vec![FieldValue::from("kept")].into()),
                    ("tag".into(), "native".into()),
                ])
                .into())
            });
            root
        });
        let updated = match harness.scenario["updated"].as_str().unwrap() {
            "undefined" => FieldValue::Undefined,
            "null" => FieldValue::Null,
            "false" => false.into(),
            "zero" => 0.into(),
            "nan" => f64::NAN.into(),
            "empty" => "".into(),
            "string" => "kept".into(),
            "function" => FieldFunction::contextual(|_, _| Ok(FieldValue::Undefined)).into(),
            "object" | "object-undefined" => updated_root.as_ref().unwrap().value.clone(),
            "array" => vec![FieldValue::from("keep"), 7.into()].into(),
            value => {
                return Err(AuthError::internal(format!(
                    "Unknown backup result: {value}"
                )));
            }
        };
        let returned_status = status.clone();
        method(&codes, "includes", harness, &visits, move |arguments| {
            assert_eq!(arguments, &[FieldValue::from("used")]);
            Ok(returned_status.clone())
        });
        let returned_updated = updated.clone();
        let expected = codes.owner();
        let observed = harness.clone();
        method(&codes, "filter", harness, &visits, move |arguments| {
            let [FieldValue::Function(predicate)] = arguments else {
                return Err(AuthError::internal(
                    "Filter requires the original predicate",
                ));
            };
            let codes = owner(&expected);
            let results = vec![
                predicate.call_with(
                    &"ignored receiver".into(),
                    &["used".into(), 9.into(), codes.clone()],
                )?,
                predicate.call_with(&codes, &[vec![FieldValue::from("used")].into()])?,
                predicate.call()?,
            ];
            assert_eq!(results, [false.into(), true.into(), true.into()]);
            observed.record(
                "filter:predicate",
                [("results".into(), observed.observe(&results.into())?)],
            );
            Ok(returned_updated.clone())
        });
        Ok(Self {
            codes,
            visits,
            status,
            updated,
            _updated_root: updated_root,
        })
    }

    fn state(&self, harness: &Harness) -> AuthResult<Json> {
        harness.observe(
            &FieldMap::from([
                ("root".into(), self.codes.value.clone()),
                ("visits".into(), self.visits.clone()),
                ("status".into(), self.status.clone()),
                ("updated".into(), self.updated.clone()),
            ])
            .into(),
        )
    }
}

struct Cipher {
    harness: Arc<Harness>,
    codes: FieldValue,
    database: OnceLock<Arc<dyn AuthStore<StatelessSchema>>>,
}

#[async_trait]
impl TwoFactorCipher for Cipher {
    async fn encrypt(&self, _: &str) -> AuthResult<String> {
        Err(AuthError::internal(
            "The native contract must not narrow the cipher input",
        ))
    }

    async fn encrypt_native(&self, plaintext: &FieldValue) -> AuthResult<FieldValue> {
        self.harness.record(
            "cipher:encrypt",
            [("value".into(), self.harness.observe(plaintext)?)],
        );
        if self.harness.scenario["fail"] == "cipher:encrypt" {
            return self.harness.fail("throw:cipher:encrypt");
        }
        if self.harness.scenario["encrypted"] == "string" {
            return Ok("encoded-native-backup-codes".into());
        }
        Ok(plaintext.clone())
    }

    async fn decrypt(&self, _: &str) -> AuthResult<String> {
        Err(AuthError::internal(
            "The native contract must not narrow the cipher result",
        ))
    }

    async fn decrypt_native(&self, ciphertext: &FieldValue) -> AuthResult<FieldValue> {
        self.harness.record(
            "cipher:decrypt",
            [
                (
                    "sameCiphertext".into(),
                    ciphertext.strict_equals(&CIPHERTEXT.into()).into(),
                ),
                ("value".into(), self.harness.observe(ciphertext)?),
            ],
        );
        assert_eq!(ciphertext, &FieldValue::from(CIPHERTEXT));
        if self.harness.scenario["replace"] == true {
            let replacement = self
                .database
                .get()
                .unwrap()
                .update_two_factor_record(
                    &"factor-row".to_owned().into(),
                    FieldMap::from([("backupCodes".into(), "concurrent-backup-ciphertext".into())]),
                )
                .await?;
            let replacement = replacement.map_or(FieldValue::Null, Into::into);
            self.harness.record(
                "cipher:replace",
                [("result".into(), self.harness.observe(&replacement)?)],
            );
        }
        Ok(self.codes.clone())
    }
}

pub(super) async fn capture(scenario: &Json) -> AuthResult<Json> {
    let harness = Arc::new(Harness::new(scenario, IDENTIFIER)?.with_model_rows(
        "twoFactor",
        EntityRole::TwoFactor,
        vec![factor()],
    ));
    let attempts_identifier = format!("2fa-attempts-{IDENTIFIER}");
    let attempts = FieldValue::from(FieldMap::from([
        ("id".into(), "attempts-row".into()),
        ("identifier".into(), attempts_identifier.clone().into()),
        ("value".into(), "0".into()),
        ("expiresAt".into(), date((NOW + 60_000) as f64)),
        ("createdAt".into(), date(NOW as f64)),
        ("updatedAt".into(), date(NOW as f64)),
    ]));
    harness.cache.insert(
        &format!("verification:{attempts_identifier}"),
        attempts.stringify()?.unwrap().into(),
    )?;
    let methods = Methods::new(&harness)?;
    let codes_before = methods.state(&harness)?;
    let cipher = Arc::new(Cipher {
        harness: harness.clone(),
        codes: methods.codes.value.clone(),
        database: OnceLock::new(),
    });
    let plugin = TwoFactorPlugin::with_config(TwoFactorConfig {
        backup_code_options: BackupCodeOptions {
            storage: BackupCodeStorage::Custom(cipher.clone()),
            ..Default::default()
        },
        ..Default::default()
    });
    let (context, inner) = harness.context(&[&plugin]).await?;
    assert!(cipher.database.set(context.database.clone()).is_ok());
    let route = <TwoFactorPlugin as AuthPlugin<StatelessSchema>>::routes(&plugin)
        .into_iter()
        .find(|route| route.path == "/two-factor/verify-backup-code")
        .unwrap();
    let cookie_name = related_cookie_name(&context.config, TWO_FACTOR_COOKIE_SUFFIX);
    let signed = sign_cookie_value(SECRET, IDENTIFIER)?;
    let headers =
        std::collections::HashMap::from([("cookie".into(), format!("{cookie_name}={signed}"))]);
    let before = harness.state(&inner)?;
    harness.activate();
    let result =
        context
            .dispatch_native(
                NativeRequest {
                    headers: Some(&headers),
                    ..Default::default()
                },
                route,
                Some(json!({"code":"used","disableSession":true})),
                None,
                |request, context| async move {
                    plugin.handle_verify_backup_code(&request, &context).await
                },
            )
            .await
            .and_then(|response| response.body.field_value());
    let mut captured = harness.finish(before, harness.outcome(result)?, &inner)?;
    captured["codes"] = json!({"before":codes_before,"after":methods.state(&harness)?});
    Ok(captured)
}

#[tokio::test]
async fn backup_code_methods_match_upstream_runtime_and_failure_persistence() -> AuthResult<()> {
    let fixture: Json = serde_json::from_str(
        &std::fs::read_to_string(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../tests/fixtures/two-factor-backup-code-native-1.7.6.json"),
        )
        .unwrap(),
    )?;
    assert_eq!(fixture["version"], "1.7.6");
    assert_eq!(fixture["contract"], "two-factor-backup-code-native");
    let cases = fixture["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 16);
    let mut failures = ReplayFailures::default();
    for case in cases {
        let name = case["name"].as_str().unwrap();
        let actual = capture(&case["scenario"]).await?;
        failures.record(name, || assert_replay(&actual, &case["runtime"], name));
    }
    failures.finish();
    Ok(())
}
