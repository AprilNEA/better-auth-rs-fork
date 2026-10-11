use super::source::{Getter, Log, Source};
use super::*;

#[derive(Clone, serde::Deserialize, serde::Serialize)]
pub(super) struct Scenario {
    pub name: String,
    pub provider: String,
    pub operation: String,
    pub shape: String,
}

impl Scenario {
    pub fn provider_id(&self) -> &'static str {
        if self.provider == "generic" {
            "generic"
        } else {
            "google"
        }
    }
}

#[derive(Default)]
pub(super) struct Tracking {
    pub info: Option<FieldValue>,
    pub mapper_input: Option<FieldValue>,
    pub subject_input: Option<FieldValue>,
    pub admissions: Vec<FieldValue>,
    pub replacements: HashMap<String, String>,
    pub session_token: Option<String>,
    pub run_start: i64,
    pub generated_dates: HashMap<String, String>,
}

pub(super) struct State {
    pub scenario: Scenario,
    pub log: Log,
    pub raw: FieldValue,
    pub mapped: FieldValue,
    pub social_response: FieldValue,
    pub marker: FieldValue,
    pub failure: FieldValue,
    pub tracking: Mutex<Tracking>,
}

impl State {
    pub fn new(scenario: Scenario) -> Arc<Self> {
        let log = Log::default();
        log.phase("setup");
        let marker = object([("source", "same-native-object".into())]);
        let failure = Source::value(
            FieldMap::from([
                ("message".into(), "Native provider profile failure".into()),
                ("name".into(), "Error".into()),
                ("code".into(), "PROFILE_NATIVE_FAILURE".into()),
                ("detail".into(), object([("retry", false.into())])),
            ]),
            None,
            log.clone(),
            FieldValue::Undefined,
            &["message", "name"],
            &[],
        );
        let mut raw = fields([
            ("id", "raw-account".into()),
            ("sub", "raw-account".into()),
            ("name", "Raw User".into()),
            ("email", EMAIL.into()),
            ("emailVerified", true.into()),
            ("image", FieldValue::Null),
            ("rawExtra", object([("kept", true.into())])),
        ]);
        let mut mapped = FieldMap::new();
        match scenario.shape.as_str() {
            "missing" | "null" => {
                for name in ["name", "email", "emailVerified", "image"] {
                    if scenario.shape == "missing" {
                        raw.remove(name);
                    } else {
                        raw.insert(name.into(), FieldValue::Null);
                    }
                }
            }
            "dynamic" => {
                raw.extend(fields([
                    ("name", vec!["Raw".into(), 3.0.into()].into()),
                    ("email", 7.0.into()),
                    ("emailVerified", vec![false.into()].into()),
                    ("image", object([("url", "native-image".into())])),
                ]));
                mapped = fields([
                    ("id", "mapped-account".into()),
                    ("name", object([("label", "Mapped".into())])),
                    ("email", 9.0.into()),
                    ("emailVerified", "verified".into()),
                    ("image", 13.0.into()),
                    ("mappedExtra", marker.clone()),
                    ("ownUndefined", FieldValue::Undefined),
                ]);
            }
            "native-business" => {
                raw.extend(fields([
                    ("name", object([("label", "Native User".into())])),
                    ("image", vec!["native-image".into(), 3.0.into()].into()),
                    ("emailVerified", "verified".into()),
                ]));
                mapped.insert("id".into(), "mapped-account".into());
            }
            "identity" => {
                mapped = fields([
                    ("id", "mapped-account".into()),
                    ("name", "Mapped User".into()),
                    ("profileExtra", marker.clone()),
                ]);
            }
            "empty-email" => {
                raw.insert("email".into(), "".into());
            }
            "dynamic-email" => {
                raw.extend(fields([
                    ("email", 7.0.into()),
                    ("name", object([("label", "Native User".into())])),
                    ("emailVerified", vec![false.into()].into()),
                    ("image", 19.0.into()),
                ]));
            }
            "falsy-defaults" => {
                raw.extend(fields([
                    ("name", 0.0.into()),
                    ("emailVerified", 0.0.into()),
                    ("image", false.into()),
                ]));
            }
            "getters" => {
                mapped = fields([
                    ("id", "mapped-account".into()),
                    ("name", object([("label", "Getter mapped".into())])),
                    ("image", FieldValue::Null),
                    ("ownUndefined", FieldValue::Undefined),
                ]);
            }
            "scalar"
            | "mapper-error"
            | "raw-getter-error"
            | "subject-error"
            | "response-spread"
            | "response-spread-error" => {}
            shape => panic!("Unknown native profile shape: {shape}"),
        }
        let raw_source = if scenario.shape == "scalar" {
            7.0.into()
        } else {
            let getters = match scenario.shape.as_str() {
                "raw-getter-error" => vec![("name", Getter::Throw)],
                "subject-error" => vec![("sub", Getter::Throw)],
                _ => Vec::new(),
            };
            Source::value(
                raw.clone(),
                Some("raw"),
                log.clone(),
                failure.clone(),
                &[],
                &getters,
            )
        };
        let mapped = Source::value(
            mapped,
            Some("mapped"),
            log.clone(),
            failure.clone(),
            &[],
            &[],
        );
        let social_response = if scenario.provider == "social" {
            let mut user = fields([
                ("id", "mapped-account".into()),
                ("name", raw.get("name").cloned().unwrap_or_default()),
                ("email", raw.get("email").cloned().unwrap_or_default()),
                (
                    "emailVerified",
                    raw.get("emailVerified").cloned().unwrap_or_default(),
                ),
                ("image", raw.get("image").cloned().unwrap_or_default()),
                ("ownUndefined", FieldValue::Undefined),
            ]);
            if scenario.shape.starts_with("response-spread") {
                user.extend(fields([
                    ("name", object([("label", "Native User".into())])),
                    ("email", 7.0.into()),
                    ("emailVerified", vec![false.into()].into()),
                    ("image", false.into()),
                ]));
            }
            let user = Source::value(user, Some("user"), log.clone(), failure.clone(), &[], &[]);
            Source::value(
                fields([
                    ("providerMeta", marker.clone()),
                    ("user", user),
                    ("account", object([("untrusted", true.into())])),
                    ("data", raw_source.clone()),
                    ("ownUndefined", FieldValue::Undefined),
                    ("tail", FieldValue::Undefined),
                    ("hidden", "not-enumerable".into()),
                ]),
                Some("response"),
                log.clone(),
                failure.clone(),
                &["hidden"],
                &[(
                    "tail",
                    if scenario.shape == "response-spread-error" {
                        Getter::ThrowingTail
                    } else {
                        Getter::Tail
                    },
                )],
            )
        } else {
            FieldValue::Undefined
        };
        log.take();
        Arc::new(Self {
            scenario,
            log,
            raw: raw_source,
            mapped,
            social_response,
            marker,
            failure,
            tracking: Mutex::new(Tracking::default()),
        })
    }

    pub fn remember(&self, value: &str, label: &str) {
        assert!(!value.is_empty(), "Generated {label} must be present");
        self.tracking
            .lock()
            .unwrap()
            .replacements
            .insert(value.into(), format!("<{label}>"));
    }

    pub fn info(&self) -> FieldValue {
        self.tracking
            .lock()
            .unwrap()
            .info
            .clone()
            .unwrap_or_default()
    }

    pub fn generated_date(&self, value: &FieldValue, offset: i64) -> AuthResult<()> {
        let FieldValue::Date(date) = value else {
            return Err(AuthError::internal("Expected a generated native Date"));
        };
        let start = self.tracking.lock().unwrap().run_start;
        let now = chrono::Utc::now().timestamp_millis();
        let base = date.milliseconds() - offset as f64;
        assert!(
            base >= start as f64 && base <= now as f64,
            "Generated date must be within its request window: {base} outside {start}..={now}"
        );
        let actual = value.json()?.unwrap().as_str().unwrap().to_owned();
        let target = FieldValue::Date(better_auth_core::FieldDate::from_milliseconds(
            (TIMESTAMP + offset) as f64,
        ))
        .json()?
        .unwrap()
        .as_str()
        .unwrap()
        .to_owned();
        self.tracking
            .lock()
            .unwrap()
            .generated_dates
            .insert(actual, target);
        Ok(())
    }

    pub fn generated_record_dates(&self, record: &FieldMap, session: bool) -> AuthResult<()> {
        for name in ["createdAt", "updatedAt"] {
            if let Some(value) = record.get(name) {
                self.generated_date(value, 0)?;
            }
        }
        if session {
            self.generated_date(record.get("expiresAt").unwrap(), 604_800_000)?;
        }
        Ok(())
    }
}
