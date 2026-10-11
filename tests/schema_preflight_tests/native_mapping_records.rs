use super::*;
use better_auth_core::{
    CreateAccount, CreateSession, CreateTeam, CreateVerification, SchemaValue, UpdateAccount,
    UpdateTeam, UpdateUser, store::database_hooks::VerificationUpdate,
};

fn date() -> FieldDate {
    FieldDate::from_milliseconds(1_893_456_000_000.0)
}
fn expiry() -> FieldDate {
    FieldDate::from_milliseconds(4_102_444_800_000.0)
}

fn data(model: Model) -> Value {
    match model {
        Model::User => {
            json!({"id":ID,"name":"source","email":"mapping-row@schema-preflight.test","emailVerified":true,"createdAt":DATE,"updatedAt":DATE})
        }
        Model::Session => {
            json!({"id":ID,"token":"source","userId":"owner","expiresAt":EXPIRY,"createdAt":DATE,"updatedAt":DATE,"ipAddress":null,"activeOrganizationId":null,"activeTeamId":null})
        }
        Model::Account => {
            json!({"id":ID,"accountId":"source","providerId":"password","userId":"owner","accessToken":null,"refreshToken":null,"idToken":null,"accessTokenExpiresAt":null,"refreshTokenExpiresAt":null,"password":null,"createdAt":DATE,"updatedAt":DATE})
        }
        Model::Verification => {
            json!({"id":ID,"identifier":"subject","value":"source","expiresAt":EXPIRY,"createdAt":DATE,"updatedAt":DATE})
        }
        Model::Team => {
            json!({"id":ID,"name":"Team","memberCount":0,"organizationId":"source","createdAt":DATE,"updatedAt":DATE})
        }
        Model::Passkey => {
            json!({"id":ID,"userId":"owner","publicKey":"source","credentialID":"credential","counter":0,"deviceType":"singleDevice","backedUp":false,"transports":null,"createdAt":DATE,"aaguid":null})
        }
    }
}

pub(super) fn expected(model: Model, input: &str) -> Value {
    let mut output = data(model);
    let (_, source, destination, _) = model.mapping();
    let fields = output.as_object_mut().unwrap();
    let _ = fields.insert(destination.into(), json!(format!("stored:{input}")));
    let _ = fields.insert(source.into(), json!(format!("visible:stored:{input}")));
    output
}

pub(super) fn stored(model: Model, old: OldColumn, input: &str) -> Value {
    let source = old.value();
    let destination = format!("stored:{input}");
    match model {
        Model::User => json!({
            "id":ID,"name":source,"email":"mapping-row@schema-preflight.test","email_verified":1,"image":destination,
            "is_anonymous":null,"phone_number":null,"phone_number_verified":null,"username":null,"display_username":null,
            "two_factor_enabled":0,"role":null,"banned":0,"ban_reason":null,"ban_expires":null,"metadata":"{}","created_at":DATE,"updated_at":DATE,
        }),
        Model::Session => json!({
            "id":ID,"token":source,"user_id":"owner","expires_at":EXPIRY,"created_at":DATE,"updated_at":DATE,"ip_address":null,
            "user_agent":destination,"impersonated_by":null,"active_organization_id":null,"active_team_id":null,"active":1,
        }),
        Model::Account => json!({
            "id":ID,"account_id":source,"provider_id":"password","user_id":"owner","access_token":null,"refresh_token":null,"id_token":null,
            "access_token_expires_at":null,"refresh_token_expires_at":null,"scope":destination,"password":null,"created_at":DATE,"updated_at":DATE,
        }),
        Model::Verification => {
            json!({"id":ID,"identifier":destination,"value":source,"expires_at":EXPIRY,"created_at":DATE,"updated_at":DATE})
        }
        Model::Team => {
            json!({"id":ID,"name":destination,"organization_id":source,"member_count":0,"created_at":DATE,"updated_at":DATE})
        }
        Model::Passkey => json!({
            "id":ID,"name":destination,"public_key":source,"user_id":"owner","credential_id":"credential","counter":0,"device_type":"singleDevice",
            "backed_up":0,"transports":null,"credential":"legacy-credential","aaguid":null,"created_at":DATE,"updated_at":DATE,
        }),
    }
}

async fn create(model: Model, store: &dyn AuthStore<BundledSchema>) -> FieldMap {
    match model {
        Model::User => {
            let mut fields = FieldMap::from_json(data(model).as_object().unwrap().clone()).unwrap();
            let _ = fields.insert("createdAt".into(), date().into());
            let _ = fields.insert("updatedAt".into(), date().into());
            store
                .create_user_fields_optional(fields)
                .await
                .unwrap()
                .unwrap()
                .into()
        }
        Model::Session => store
            .create_session(CreateSession {
                inherited_fields: Default::default(),
                additional_fields: [
                    ("token".into(), "source".into()),
                    ("ipAddress".into(), FieldValue::Null),
                    ("userAgent".into(), FieldValue::Undefined),
                    ("activeOrganizationId".into(), FieldValue::Null),
                    ("activeTeamId".into(), FieldValue::Null),
                    ("createdAt".into(), date().into()),
                    ("updatedAt".into(), date().into()),
                ]
                .into(),
                user_id: "owner".into(),
                expires_at: expiry(),
                ip_address: None,
                user_agent: None,
                impersonated_by: None,
                active_organization_id: None,
            })
            .await
            .unwrap()
            .into(),
        Model::Account => store
            .create_account(CreateAccount {
                id: ID.into(),
                account_id: "source".into(),
                provider_id: "password".into(),
                user_id: "owner".into(),
                access_token: SchemaValue::from_field(FieldValue::Null),
                refresh_token: SchemaValue::from_field(FieldValue::Null),
                id_token: SchemaValue::from_field(FieldValue::Null),
                access_token_expires_at: SchemaValue::from_field(FieldValue::Null),
                refresh_token_expires_at: SchemaValue::from_field(FieldValue::Null),
                password: SchemaValue::from_field(FieldValue::Null),
                created_at: date().into(),
                updated_at: date().into(),
                ..Default::default()
            })
            .await
            .unwrap()
            .internal_fields()
            .unwrap(),
        Model::Verification => store
            .create_verification(CreateVerification {
                id: ID.into(),
                identifier: "subject".into(),
                value: "source".into(),
                expires_at: expiry().into(),
                created_at: date().into(),
                updated_at: date().into(),
                ..Default::default()
            })
            .await
            .unwrap()
            .fields()
            .unwrap(),
        Model::Team => store
            .create_team(CreateTeam {
                id: Some(ID.into()),
                name: "Team".into(),
                organization_id: "source".into(),
                created_at: Some(date()),
                updated_at: Some(date()),
                additional_fields: Default::default(),
            })
            .await
            .unwrap()
            .field_values()
            .unwrap(),
        Model::Passkey => {
            let mut fields = FieldMap::from_json(data(model).as_object().unwrap().clone()).unwrap();
            let _ = fields.insert("createdAt".into(), date().into());
            store.create_passkey_record(fields).await.unwrap().unwrap()
        }
    }
}

async fn update(model: Model, store: &dyn AuthStore<BundledSchema>) -> FieldMap {
    match model {
        Model::User => store
            .update_user(
                ID,
                UpdateUser {
                    name: Some("next".into()).into(),
                    additional_fields: [("updatedAt".into(), date().into())].into(),
                    ..Default::default()
                },
            )
            .await
            .unwrap()
            .into(),
        Model::Session => store
            .update_session_fields(
                "stored:source",
                [
                    ("token".into(), "next".into()),
                    ("updatedAt".into(), date().into()),
                ]
                .into(),
            )
            .await
            .unwrap()
            .unwrap()
            .into(),
        Model::Account => store
            .update_account(
                ID,
                UpdateAccount {
                    account_id: "next".into(),
                    updated_at: date().into(),
                    ..Default::default()
                },
            )
            .await
            .unwrap()
            .internal_fields()
            .unwrap(),
        Model::Verification => store
            .update_verification(
                "stored:source",
                VerificationUpdate {
                    value: "next".into(),
                    updated_at: date().into(),
                    ..Default::default()
                },
            )
            .await
            .unwrap()
            .unwrap()
            .fields()
            .unwrap(),
        Model::Team => store
            .update_team(
                ID,
                UpdateTeam {
                    organization_id: Some("next".into()),
                    updated_at: Some(Some(date())),
                    ..Default::default()
                },
            )
            .await
            .unwrap()
            .field_values()
            .unwrap(),
        Model::Passkey => store
            .update_passkey_record(&ID.into(), [("publicKey".into(), "next".into())].into())
            .await
            .unwrap()
            .unwrap(),
    }
}

pub(super) async fn read(
    model: Model,
    input: &str,
    store: &dyn AuthStore<BundledSchema>,
) -> Option<FieldMap> {
    let selector = format!("stored:{input}");
    match model {
        Model::User => store.get_user_by_id(ID).await.unwrap().map(FieldMap::from),
        Model::Session => store
            .get_session(&selector)
            .await
            .unwrap()
            .map(FieldMap::from),
        Model::Account => store
            .get_account("password", &selector)
            .await
            .unwrap()
            .map(|row| row.internal_fields().unwrap()),
        Model::Verification => store
            .get_verification_by_identifier(&selector)
            .await
            .unwrap()
            .map(|row| row.fields().unwrap()),
        Model::Team => store
            .get_team(ID)
            .await
            .unwrap()
            .map(|row| row.field_values().unwrap()),
        Model::Passkey => store.get_passkey_record(&ID.into()).await.unwrap(),
    }
}

pub(super) async fn run(
    model: Model,
    stage: Stage,
    input: &str,
    store: &dyn AuthStore<BundledSchema>,
) -> FieldMap {
    match stage {
        Stage::Create => create(model, store).await,
        Stage::Update => update(model, store).await,
        Stage::Read => read(model, input, store).await.unwrap(),
    }
}

pub(super) async fn delete(model: Model, store: &dyn AuthStore<BundledSchema>) {
    match model {
        Model::User => store.delete_user(ID).await.unwrap(),
        Model::Session => store.delete_session("stored:next").await.unwrap(),
        Model::Account => store.delete_account(ID).await.unwrap(),
        Model::Verification => store.delete_verification(ID).await.unwrap(),
        Model::Team => store.delete_team(ID).await.unwrap(),
        Model::Passkey => store.delete_passkey(ID).await.unwrap(),
    }
}
