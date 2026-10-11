use super::*;
use better_auth_core::{
    ApiKey, ApiKeyView, CreateApiKey, CreateJwk, CreateTwoFactor, CreateWalletAddress, Jwk,
    TwoFactor, UpdateApiKey, UpdateTwoFactor, WalletAddress,
};

#[derive(Clone, Copy, Debug)]
pub(super) enum Model {
    ApiKey,
    TwoFactor,
    Jwk,
    Wallet,
}

impl Model {
    pub(super) const ALL: [Self; 4] = [Self::ApiKey, Self::TwoFactor, Self::Jwk, Self::Wallet];

    pub(super) fn role(self) -> EntityRole {
        match self {
            Self::ApiKey => EntityRole::ApiKey,
            Self::TwoFactor => EntityRole::TwoFactor,
            Self::Jwk => EntityRole::Jwk,
            Self::Wallet => EntityRole::WalletAddress,
        }
    }

    pub(super) fn target(self) -> &'static str {
        match self {
            Self::ApiKey => "enabled",
            Self::TwoFactor => "verified",
            Self::Jwk => "alg",
            Self::Wallet => "chainId",
        }
    }

    pub(super) fn columns(self) -> (&'static str, &'static str, &'static str) {
        match self {
            Self::ApiKey => ("api_keys", "remaining", "enabled"),
            Self::TwoFactor => ("ordinary_two_factor_fields", "backup_codes", "verified"),
            Self::Jwk => ("jwks", "crv", "alg"),
            Self::Wallet => ("wallet_address", "created_at", "chain_id"),
        }
    }

    pub(super) fn selector(self) -> Option<(&'static str, &'static str, &'static str)> {
        match self {
            Self::TwoFactor => Some(("userId", "user_id", "owner")),
            Self::Wallet => Some(("address", "address", "wallet")),
            _ => None,
        }
    }

    pub(super) fn value(self, create: bool) -> FieldValue {
        match self {
            Self::ApiKey | Self::TwoFactor => create.into(),
            Self::Jwk => if create { "first-alg" } else { "next-alg" }.into(),
            Self::Wallet => if create { 1.0 } else { 2.0 }.into(),
        }
    }

    pub(super) fn field_type(self) -> UserFieldType {
        match self {
            Self::ApiKey | Self::TwoFactor => UserFieldType::Boolean,
            Self::Jwk => UserFieldType::String,
            Self::Wallet => UserFieldType::Number,
        }
    }

    pub(super) fn fields(self, marker: &str, target: FieldValue) -> FieldMap {
        let mut fields = FieldMap::from([
            ("marker".into(), marker.into()),
            (self.target().into(), target),
        ]);
        if let Some((name, _, value)) = self.selector() {
            let _ = fields.insert(name.into(), value.into());
        }
        let _ = fields.insert("id".into(), ID.into());
        fields
    }

    pub(super) async fn raw<S: AuthSchema>(
        self,
        store: &dyn AuthStore<S>,
        stage: &str,
        marker: &str,
    ) -> AuthResult<FieldMap> {
        let create = stage == "create";
        let input = self.fields(marker, self.value(create));
        let id = ID.into();
        let result = if create {
            match self {
                Self::ApiKey => store.create_api_key_record(input).await?,
                Self::TwoFactor => store.create_two_factor_record(input).await?,
                Self::Jwk => store.create_jwk_record(input).await?,
                Self::Wallet => store.create_wallet_address_record(input).await?,
            }
        } else if writes(stage) {
            let mut input = input;
            let _ = input.remove("id");
            if let Some((selector, _, _)) = self.selector() {
                let _ = input.remove(selector);
            }
            match self {
                Self::ApiKey => store.update_api_key_record(&id, input).await?,
                Self::TwoFactor => store.update_two_factor_record(&id, input).await?,
                Self::Jwk => store.update_jwk_record(&id, input).await?,
                Self::Wallet => store.update_wallet_address_record(&id, input).await?,
            }
        } else {
            match self {
                Self::ApiKey => store.get_api_key_record(&id).await?,
                Self::TwoFactor => store.get_two_factor_record(&id).await?,
                Self::Jwk => store.get_jwk_record(&id).await?,
                Self::Wallet => store.get_wallet_address_record(&id).await?,
            }
        };
        result.ok_or_else(|| AuthError::internal("Expected the raw plugin record"))
    }

    pub(super) async fn typed<S: AuthSchema>(
        self,
        store: &dyn AuthStore<S>,
        stage: &str,
        marker: &str,
    ) -> AuthResult<FieldMap> {
        let extras = FieldMap::from([
            ("marker".into(), marker.into()),
            ("id".into(), ID.into()),
            ("undeclared".into(), true.into()),
        ]);
        let id = ID.into();
        let record = if stage == "create" {
            match self {
                Self::ApiKey => Record::ApiKey(Box::new(
                    store
                        .create_api_key(CreateApiKey {
                            additional_fields: extras,
                            reference_id: "owner".into(),
                            config_id: "default".into(),
                            name: Some("undeclared".into()).into(),
                            prefix: None,
                            key_hash: "private".into(),
                            start: None,
                            expires_at: None,
                            remaining: None,
                            rate_limit_enabled: false,
                            rate_limit_time_window: None,
                            rate_limit_max: None,
                            refill_interval: None,
                            refill_amount: None,
                            permissions: None.into(),
                            metadata: None,
                            enabled: true.into(),
                        })
                        .await?,
                )),
                Self::TwoFactor => Record::TwoFactor(
                    store
                        .create_two_factor(CreateTwoFactor {
                            additional_fields: extras,
                            user_id: "owner".into(),
                            secret: "undeclared".into(),
                            backup_codes: "undeclared".into(),
                            verified: true,
                        })
                        .await?,
                ),
                Self::Jwk => Record::Jwk(
                    store
                        .create_jwk(CreateJwk {
                            additional_fields: extras,
                            public_key: "undeclared".into(),
                            private_key: "private".into(),
                            created_at: FieldDate::from_milliseconds(0.0),
                            expires_at: None,
                            alg: "first-alg".into(),
                            crv: None,
                        })
                        .await?,
                ),
                Self::Wallet => Record::Wallet(
                    store
                        .create_wallet_address(CreateWalletAddress {
                            additional_fields: extras,
                            user_id: "owner".into(),
                            address: "wallet".into(),
                            chain_id: 1,
                            is_primary: false,
                            created_at: FieldDate::from_milliseconds(0.0),
                        })
                        .await?,
                ),
            }
        } else if writes(stage) {
            let mut extras = extras;
            let _ = extras.remove("id");
            match self {
                Self::ApiKey => Record::ApiKey(Box::new(
                    store
                        .update_api_key(
                            &id,
                            UpdateApiKey {
                                additional_fields: extras,
                                enabled: Some(false.into()),
                                ..Default::default()
                            },
                        )
                        .await?,
                )),
                Self::TwoFactor => Record::TwoFactor(
                    store
                        .update_two_factor(
                            &id,
                            UpdateTwoFactor {
                                additional_fields: extras,
                                verified: Some(false),
                                ..Default::default()
                            },
                        )
                        .await?,
                ),
                // These models expose complete record patches and typed reads, without a typed update DTO.
                Self::Jwk => Record::Jwk(Jwk::from_field_values(
                    self.raw(store, stage, marker).await?,
                )?),
                Self::Wallet => Record::Wallet(WalletAddress::from_field_values(
                    self.raw(store, stage, marker).await?,
                )?),
            }
        } else {
            match self {
                Self::ApiKey => Record::ApiKey(Box::new(
                    store.get_api_key_by_id(ID).await?.ok_or_else(missing)?,
                )),
                Self::TwoFactor => Record::TwoFactor(
                    store
                        .get_two_factor_by_user_id("owner")
                        .await?
                        .ok_or_else(missing)?,
                ),
                Self::Jwk => Record::Jwk(store.get_jwk(ID).await?.ok_or_else(missing)?),
                Self::Wallet => Record::Wallet(
                    store
                        .get_wallet_address("wallet", None)
                        .await?
                        .ok_or_else(missing)?,
                ),
            }
        };
        record.observe()
    }
}

fn missing() -> AuthError {
    AuthError::internal("Expected the typed plugin record")
}

enum Record {
    ApiKey(Box<ApiKey>),
    TwoFactor(TwoFactor),
    Jwk(Jwk),
    Wallet(WalletAddress),
}

fn json<T: serde::Serialize + serde::de::DeserializeOwned>(
    row: &T,
    fields: &FieldMap,
) -> AuthResult<()> {
    let expected = FieldValue::from(fields.clone())
        .stringify()?
        .ok_or_else(missing)?;
    assert_eq!(
        serde_json::to_string(row)?,
        expected,
        "Complete typed JSON and canonical property order"
    );
    let restored: T = serde_json::from_str(&expected)?;
    assert_eq!(
        serde_json::to_string(&restored)?,
        expected,
        "JSON reconstruction must not reorder native fields"
    );
    Ok(())
}

impl Record {
    fn observe(self) -> AuthResult<FieldMap> {
        let fields = match self {
            Self::ApiKey(row) => {
                let fields = row.field_values()?;
                json(&row, &fields)?;
                let view = ApiKeyView::try_from_api_key(row.as_ref())?;
                let mut expected = fields.clone();
                let _ = expected.insert("metadata".into(), FieldValue::Undefined);
                let _ = expected.insert("permissions".into(), FieldValue::Null);
                exact(&view.field_values()?, &expected);
                json(&view, &expected)?;
                fields
            }
            Self::TwoFactor(row) => {
                let fields = row.field_values()?;
                json(&row, &fields)?;
                fields
            }
            Self::Jwk(row) => row.field_values()?,
            Self::Wallet(row) => {
                let fields = row.field_values()?;
                json(&row, &fields)?;
                fields
            }
        };
        Ok(fields)
    }
}
