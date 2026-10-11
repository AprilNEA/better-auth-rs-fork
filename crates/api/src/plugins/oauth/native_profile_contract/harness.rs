use super::super::{OAuthPlugin, OAuthProvider};
use super::*;
use better_auth_core::{
    AuthConfig, AuthContext, AuthPlugin, OAuthStateStrategy,
    endpoint_dispatch::EndpointDispatcher,
    id::{IdGeneration, IdGenerator},
    store::{EphemeralStore, StatelessSchema},
    user_fields::{UserFieldConfig, UserFieldType},
};

pub(super) struct Harness {
    pub context: AuthContext<StatelessSchema>,
    pub store: EphemeralStore,
    pub plugin: OAuthPlugin,
    pub dispatcher: EndpointDispatcher<StatelessSchema>,
    _token_server: Option<server::TokenServer>,
}

impl Harness {
    pub async fn new(state: &Arc<State>) -> AuthResult<Self> {
        let mut config = AuthConfig::new(SECRET).base_url(ORIGIN);
        config.account.store_state_strategy = Some(OAuthStateStrategy::Database);
        let generated = Mutex::new(HashMap::<String, usize>::new());
        config.advanced.database.generate_id =
            Some(IdGeneration::Custom(IdGenerator::new(move |request| {
                let mut generated = generated.lock().unwrap();
                let next = generated.entry(request.model.into()).or_default();
                *next += 1;
                Ok(Some(format!("{}-{next}", request.model)))
            })));
        config.user.fields_mut().insert(
            "profileExtra".into(),
            UserFieldConfig {
                field_type: UserFieldType::Json,
                required: Some(false),
                ..Default::default()
            },
        );
        let config = Arc::new(config);
        let store = EphemeralStore::from_storage(config.clone(), seed(&state.scenario))?;
        let callbacks = Arc::new(callbacks::Callbacks(state.clone()));
        let token_server =
            if state.scenario.provider == "social" && state.scenario.operation == "callback" {
                Some(server::TokenServer::new(state.clone()).await?)
            } else {
                None
            };
        let plugin = if state.scenario.provider == "generic" {
            OAuthPlugin::new().add_generic_provider("generic", callbacks::generic(&callbacks))
        } else {
            let mut provider = OAuthProvider::google("client", "secret");
            provider.get_user_info = Some(callbacks.clone());
            provider.map_profile_to_user = Some(callbacks.clone());
            provider.account_subject = Some(callbacks.clone());
            provider.verify_id_token = Some(callbacks.clone());
            if let Some(server) = &token_server {
                provider.token_url = server.url.clone();
            }
            OAuthPlugin::new().add_provider("google", provider)
        };
        let hooks = hooks::Hooks(state.clone());
        let mut context = crate::plugins::test_helpers::initialize_test_context(
            config,
            Arc::new(store.clone()),
            &[&plugin, &hooks],
        )
        .await?;
        let admission: Arc<dyn crate::plugins::user_admission::ValidateUserInfo<StatelessSchema>> =
            callbacks;
        context.extensions.insert(admission);
        let routes = AuthPlugin::<StatelessSchema>::routes(&plugin);
        let dispatcher = EndpointDispatcher::new(Arc::new(Vec::new()), Default::default(), routes);
        state.log.take();
        Ok(Self {
            context,
            store,
            plugin,
            dispatcher,
            _token_server: token_server,
        })
    }
}

fn seed(scenario: &Scenario) -> Vec<(String, Vec<FieldMap>)> {
    let (users, accounts) = if scenario.operation == "account-info" {
        let date: FieldValue =
            better_auth_core::FieldDate::from_milliseconds(TIMESTAMP as f64).into();
        assert_eq!(date.json().unwrap(), Some(json!(DATE)));
        let user = fields([
            ("id", "owner".into()),
            ("name", "Stored User".into()),
            ("email", EMAIL.into()),
            ("emailVerified", true.into()),
            ("image", FieldValue::Null),
            ("createdAt", date.clone()),
            ("updatedAt", date.clone()),
        ]);
        let account = fields([
            ("id", "stored-account".into()),
            ("userId", "owner".into()),
            ("providerId", scenario.provider_id().into()),
            ("accountId", "stored-provider-id".into()),
            ("accessToken", ACCESS_TOKEN.into()),
            ("refreshToken", FieldValue::Null),
            ("idToken", FieldValue::Null),
            ("accessTokenExpiresAt", FieldValue::Null),
            ("refreshTokenExpiresAt", FieldValue::Null),
            ("scope", "profile".into()),
            ("password", FieldValue::Null),
            ("createdAt", date.clone()),
            ("updatedAt", date),
        ]);
        (vec![user], vec![account])
    } else {
        (Vec::new(), Vec::new())
    };
    vec![
        ("user".into(), users),
        ("session".into(), Vec::new()),
        ("account".into(), accounts),
        ("verification".into(), Vec::new()),
    ]
}
