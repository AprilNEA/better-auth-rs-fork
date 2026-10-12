use super::*;

pub(super) const SECRET: &str = "update-user-native-session-secret-at-least-32-characters";
pub(super) const ORIGIN: &str = "http://update-user-session.test";
pub(super) const EXPIRES: f64 = 4_102_444_800_000.0;
pub(super) const CASES: &[&str] = &[
    "matched",
    "numeric-id",
    "missing-id",
    "null-id",
    "undefined-id",
    "false-user",
    "number-user",
    "string-user",
    "array-user",
    "null-user",
    "undefined-user",
    "cancel",
    "before-error",
    "after-error",
    "output-transform",
    "image-only",
    "null-name",
    "null-no-fields",
    "undefined-email",
    "getter-id",
    "getter-cancel",
    "getter-error",
    "getter-no-fields",
    "getter-email",
    "getter-fallback-error",
];

pub(super) fn lock<T>(value: &Mutex<T>) -> AuthResult<std::sync::MutexGuard<'_, T>> {
    value
        .lock()
        .map_err(|_| AuthError::internal("Update-user recorder mutex poisoned"))
}

pub(super) fn date() -> FieldValue {
    FieldDate::from_milliseconds(1_893_456_000_000.0).into()
}

pub(super) fn user(id: &str) -> FieldMap {
    FieldMap::from([
        ("name".into(), "Stored".into()),
        ("email".into(), format!("{id}@update-user.test").into()),
        ("emailVerified".into(), true.into()),
        ("image".into(), FieldValue::Null),
        ("createdAt".into(), date()),
        ("updatedAt".into(), date()),
        ("marker".into(), "old".into()),
        ("private".into(), true.into()),
        ("id".into(), id.into()),
    ])
}

pub(super) fn session(token: &str, user_id: &str) -> FieldMap {
    FieldMap::from([
        ("id".into(), format!("{token}-id").into()),
        (
            "expiresAt".into(),
            FieldDate::from_milliseconds(EXPIRES).into(),
        ),
        ("token".into(), token.into()),
        ("createdAt".into(), date()),
        ("updatedAt".into(), date()),
        ("ipAddress".into(), FieldValue::Null),
        ("userAgent".into(), FieldValue::Null),
        ("userId".into(), user_id.into()),
    ])
}

pub(super) fn snapshot_user(case: &str, shared: &FieldValue) -> FieldValue {
    match case {
        "false-user" => false.into(),
        "number-user" => 7.into(),
        "string-user" => "ab".into(),
        "array-user" => vec![shared.clone(), shared.clone()].into(),
        "null-user" | "null-no-fields" => FieldValue::Null,
        "undefined-user" | "undefined-email" => FieldValue::Undefined,
        _ => {
            let mut fields = FieldMap::from([
                ("name".into(), false.into()),
                ("image".into(), 9.into()),
                ("email".into(), FieldValue::Null),
                ("emailVerified".into(), "dynamic".into()),
                ("private".into(), false.into()),
                ("ownUndefined".into(), FieldValue::Undefined),
                ("shared".into(), shared.clone()),
                ("alias".into(), shared.clone()),
            ]);
            if case != "missing-id" {
                let id = match case {
                    "numeric-id" => 7.into(),
                    "null-id" => FieldValue::Null,
                    "undefined-id" | "getter-fallback-error" => FieldValue::Undefined,
                    _ => "7".into(),
                };
                let _ = fields.insert("id".into(), id);
            }
            if matches!(case, "getter-id" | "getter-fallback-error") {
                let _ = fields.insert("unread".into(), FieldValue::Null);
            }
            fields.into()
        }
    }
}

pub(super) fn body(case: &str) -> Value {
    match case {
        "image-only" => json!({"image":null}),
        "null-name" => json!({"name":null}),
        "null-no-fields" | "getter-no-fields" => json!({}),
        "undefined-email" | "getter-email" => json!({"email":"changed@update-user.test"}),
        _ => json!({"name":17,"marker":"next"}),
    }
}

pub(super) fn matches_row(case: &str) -> bool {
    matches!(
        case,
        "matched"
            | "cancel"
            | "before-error"
            | "after-error"
            | "output-transform"
            | "image-only"
            | "null-name"
            | "getter-id"
            | "getter-cancel"
    )
}

pub(super) fn fails(case: &str) -> bool {
    matches!(
        case,
        "null-user"
            | "undefined-user"
            | "before-error"
            | "after-error"
            | "null-no-fields"
            | "undefined-email"
            | "getter-error"
            | "getter-no-fields"
            | "getter-email"
            | "getter-fallback-error"
    )
}

#[derive(Clone, Default)]
pub(super) struct Observed {
    pub(super) events: Vec<String>,
    pub(super) inputs: Vec<FieldMap>,
    pub(super) updates: Vec<Option<FieldMap>>,
    pub(super) issued: Vec<Option<NativeSessionData>>,
    pub(super) versions: Vec<NativeSessionData>,
}

#[derive(Clone)]
pub(super) struct SessionHooks {
    pub(super) case: &'static str,
    pub(super) data: NativeSessionData,
    pub(super) thrown: FieldValue,
    pub(super) state: Arc<Mutex<Observed>>,
}

impl SessionHooks {
    pub(super) fn event(&self, name: &str) -> AuthResult<()> {
        lock(&self.state)?.events.push(name.into());
        Ok(())
    }
}

#[async_trait]
impl BeforeEndpointHook<S> for SessionHooks {
    async fn before(
        &self,
        _: &AuthRequest,
        _: &AuthContext<S>,
    ) -> AuthResult<Option<BeforeRequestAction>> {
        self.event("endpoint.before")?;
        Ok(Some(BeforeRequestAction::InjectNativeSession {
            session: Box::new(self.data.clone()),
        }))
    }
}

#[async_trait]
impl AfterEndpointHook<S> for SessionHooks {
    async fn after(
        &self,
        request: &AuthRequest,
        _: &mut AuthResponse,
        _: &AuthContext<S>,
    ) -> AuthResult<()> {
        self.event("endpoint.after")?;
        lock(&self.state)?.issued.push(request.new_session()?);
        Ok(())
    }
}

#[better_auth::database_hooks]
impl DatabaseHooks<S> for SessionHooks {
    async fn before_update_user(
        &self,
        data: &mut FieldMap,
        _: &DatabaseHookContext<'_, S>,
    ) -> AuthResult<DatabaseHookUpdate<FieldMap>> {
        self.event("db.before")?;
        lock(&self.state)?.inputs.push(data.clone());
        match self.case {
            "cancel" | "getter-cancel" => Ok(DatabaseHookUpdate::Cancel),
            "before-error" => Err(AuthError::from_thrown(self.thrown.clone())),
            _ => Ok(DatabaseHookUpdate::Continue),
        }
    }
    async fn after_update_user(
        &self,
        user: Option<&UserView>,
        _: &DatabaseHookContext<'_, S>,
    ) -> AuthResult<()> {
        self.event("db.after")?;
        lock(&self.state)?
            .updates
            .push(user.cloned().map(FieldMap::from));
        if self.case == "after-error" {
            Err(AuthError::from_thrown(self.thrown.clone()))
        } else {
            Ok(())
        }
    }
}

#[async_trait]
impl AuthPlugin<S> for SessionHooks {
    fn name(&self) -> &'static str {
        "update-user-native-session-contract"
    }
    fn routes(&self) -> Vec<AuthRoute> {
        Vec::new()
    }
    async fn on_request(
        &self,
        _: &AuthRequest,
        _: &AuthContext<S>,
    ) -> AuthResult<Option<AuthResponse>> {
        Ok(None)
    }
    async fn on_init(&self, context: &mut AuthInitContext<S>) -> AuthResult<()> {
        context.register_database_hook(Arc::new(self.clone()));
        Ok(())
    }
}

pub(super) struct Cache {
    pub(super) values: Mutex<BTreeMap<String, String>>,
    pub(super) state: Arc<Mutex<Observed>>,
}

#[async_trait]
impl SecondaryStorage for Cache {
    async fn get(&self, key: &str) -> AuthResult<Option<Value>> {
        lock(&self.state)?.events.push(format!("cache.get:{key}"));
        Ok(lock(&self.values)?.get(key).cloned().map(Value::String))
    }
    async fn set_native(
        &self,
        key: &FieldValue,
        value: &FieldValue,
        ttl: Option<f64>,
    ) -> AuthResult<()> {
        let key = key
            .as_str()
            .ok_or_else(|| AuthError::internal("Expected native string cache key"))?;
        let ttl = ttl.ok_or_else(|| AuthError::internal("Expected refresh TTL"))?;
        let expected = (EXPIRES - chrono::Utc::now().timestamp_millis() as f64) / 1_000.0;
        assert!((expected - 1.0..=expected + 1.0).contains(&ttl));
        lock(&self.state)?.events.push(format!("cache.set:{key}"));
        let _ = lock(&self.values)?.insert(key.into(), value.decode()?);
        Ok(())
    }
    async fn delete(&self, _: &str) -> AuthResult<()> {
        Err(AuthError::internal(
            "Update-user must not delete cache entries",
        ))
    }
    async fn get_and_delete(&self, _: &str) -> AuthResult<Option<Value>> {
        Err(AuthError::internal(
            "Update-user must not consume cache entries",
        ))
    }
}

pub(super) fn expected_fields(case: &str, mut fields: FieldMap) -> FieldMap {
    match case {
        "image-only" => {
            let _ = fields.insert("image".into(), FieldValue::Null);
        }
        "null-name" => {
            let _ = fields.insert("name".into(), FieldValue::Null);
        }
        _ => {
            let _ = fields.insert("name".into(), 17.into());
            let _ = fields.insert("marker".into(), "next".into());
        }
    }
    fields
}

pub(super) fn ordered(actual: &FieldMap, expected: &FieldMap) {
    assert_eq!(
        actual.keys().collect::<Vec<_>>(),
        expected.keys().collect::<Vec<_>>()
    );
    assert_eq!(actual, expected);
}
