#![expect(
    clippy::panic_in_result_fn,
    reason = "The alias contract asserts complete records and ActiveModel writes while propagating adapter errors."
)]

use super::*;
use better_auth::{
    __private_core::user_fields::AdapterRecord,
    seaorm::{SeaOrmAccountModel, SeaOrmOrganizationModel, SeaOrmVerificationModel},
};

const NOW: &str = "2030-01-02T03:04:05.000Z";

mod account {
    use super::*;

    #[derive(Clone, Debug, PartialEq, serde::Serialize, DeriveEntityModel, AuthEntity)]
    #[auth(role = "account")]
    #[sea_orm(table_name = "mapped_accounts")]
    pub struct Model {
        #[sea_orm(primary_key, auto_increment = false)]
        pub id: String,
        #[sea_orm(column_name = "stored_account")]
        pub account_id: String,
        pub provider_id: String,
        pub user_id: String,
        pub access_token: Option<String>,
        pub refresh_token: Option<String>,
        pub id_token: Option<String>,
        pub access_token_expires_at: Option<DateTimeUtc>,
        pub refresh_token_expires_at: Option<DateTimeUtc>,
        pub scope: Option<String>,
        pub password: Option<String>,
        pub created_at: DateTimeUtc,
        pub updated_at: DateTimeUtc,
    }

    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}
    impl ActiveModelBehavior for ActiveModel {}
}

mod verification {
    use super::*;

    #[derive(Clone, Debug, PartialEq, serde::Serialize, DeriveEntityModel, AuthEntity)]
    #[auth(role = "verification")]
    #[sea_orm(table_name = "mapped_verifications")]
    pub struct Model {
        #[sea_orm(primary_key, auto_increment = false)]
        pub id: String,
        pub identifier: String,
        #[sea_orm(column_name = "stored_value")]
        pub value: String,
        pub expires_at: DateTimeUtc,
        pub created_at: DateTimeUtc,
        pub updated_at: DateTimeUtc,
    }

    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}
    impl ActiveModelBehavior for ActiveModel {}
}

mod organization {
    use super::*;

    #[derive(Clone, Debug, PartialEq, serde::Serialize, DeriveEntityModel, AuthEntity)]
    #[auth(role = "organization")]
    #[sea_orm(table_name = "mapped_organizations")]
    pub struct Model {
        #[sea_orm(primary_key, auto_increment = false)]
        pub id: String,
        #[sea_orm(column_name = "stored_name")]
        pub name: String,
        pub slug: String,
        pub logo: Option<String>,
        pub metadata: Option<String>,
        pub created_at: DateTimeUtc,
        pub auth_updated_at: DateTimeUtc,
        #[sea_orm(column_name = "stored_label")]
        pub audit_label: String,
    }

    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}
    impl ActiveModelBehavior for ActiveModel {}
}

fn mappings(fields: &[(&str, &str)]) -> UserConfig {
    UserConfig {
        additional_fields: Some(
            fields
                .iter()
                .map(|(logical, physical)| {
                    (
                        (*logical).into(),
                        UserFieldConfig {
                            field_name: Some((*physical).into()),
                            ..Default::default()
                        },
                    )
                })
                .collect(),
        ),
    }
}

async fn project(fields: &UserConfig, record: AdapterRecord) -> AuthResult<serde_json::Value> {
    let output = fields
        .project_adapter_records(vec![record], false, true)
        .await?;
    Ok(serde_json::to_value(
        output
            .iter()
            .map(FieldMap::json)
            .collect::<AuthResult<Vec<_>>>()?,
    )?)
}

#[tokio::test]
async fn account_and_verification_column_names_support_writes_and_projection_without_serde_renaming()
-> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    use sea_orm::ActiveValue::Set;
    let now = NOW.parse::<DateTimeUtc>()?;
    let mut active = account::Model {
        id: "account".into(),
        account_id: "before".into(),
        provider_id: "provider".into(),
        user_id: "user".into(),
        access_token: None,
        refresh_token: None,
        id_token: None,
        access_token_expires_at: None,
        refresh_token_expires_at: None,
        scope: None,
        password: None,
        created_at: now,
        updated_at: now,
    }
    .into_active_model();
    for alias in ["account_id", "accountId", "stored_account"] {
        assert!(matches!(
            account::Model::field_column(alias)?,
            account::Column::AccountId
        ));
        account::Model::apply_fields(&mut active, FieldMap::from([(alias.into(), alias.into())]))?;
        assert_eq!(active.account_id, Set(alias.into()));
    }
    let model = active.try_into_model()?;
    let serialized = serde_json::to_value(&model)?;
    assert_eq!(serialized.get("account_id"), Some(&json!("stored_account")));
    assert!(serialized.get("stored_account").is_none());
    let fields = mappings(&[("accountId", "stored_account")]);
    assert_eq!(
        project(&fields, model.record_fields(&fields)?).await?,
        json!([{
            "id":"account", "accountId":"stored_account", "providerId":"provider", "userId":"user",
            "accessToken":null, "refreshToken":null, "idToken":null, "accessTokenExpiresAt":null,
            "refreshTokenExpiresAt":null, "scope":null, "password":null, "createdAt":NOW, "updatedAt":NOW,
        }])
    );

    let mut active = verification::Model {
        id: "verification".into(),
        identifier: "identifier".into(),
        value: "before".into(),
        expires_at: now,
        created_at: now,
        updated_at: now,
    }
    .into_active_model();
    assert!(matches!(
        verification::Model::field_column("stored_value")?,
        verification::Column::Value
    ));
    verification::Model::apply_fields(
        &mut active,
        FieldMap::from([("stored_value".into(), "after".into())]),
    )?;
    assert_eq!(active.value, Set("after".into()));
    let model = active.try_into_model()?;
    let fields = mappings(&[("value", "stored_value")]);
    assert_eq!(
        project(&fields, model.record_fields(&fields)?).await?,
        json!([{
            "id":"verification", "identifier":"identifier", "value":"after",
            "expiresAt":NOW, "createdAt":NOW, "updatedAt":NOW,
        }])
    );
    Ok(())
}

#[tokio::test]
async fn organization_column_names_map_core_and_extra_fields_without_serde_renaming()
-> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    use sea_orm::ActiveValue::Set;
    let now = NOW.parse::<DateTimeUtc>()?;
    let mut active = organization::Model {
        id: "organization".into(),
        name: "before".into(),
        slug: "slug".into(),
        logo: None,
        metadata: None,
        created_at: now,
        auth_updated_at: now,
        audit_label: "before".into(),
    }
    .into_active_model();
    assert!(matches!(
        organization::Model::column("stored_name")?,
        organization::Column::Name
    ));
    organization::Model::apply_fields(
        &mut active,
        FieldMap::from([("stored_name".into(), "after".into())]),
    )?;
    assert_eq!(active.name, Set("after".into()));
    for alias in ["audit_label", "auditLabel", "stored_label"] {
        assert!(matches!(
            organization::Model::column(alias)?,
            organization::Column::AuditLabel
        ));
        organization::Model::apply_fields(
            &mut active,
            FieldMap::from([(alias.into(), alias.into())]),
        )?;
        assert_eq!(active.audit_label, Set(alias.into()));
    }
    let model = active.try_into_model()?;
    let serialized = serde_json::to_value(&model)?;
    assert_eq!(serialized.get("audit_label"), Some(&json!("stored_label")));
    assert!(serialized.get("stored_label").is_none());
    let fields = mappings(&[("name", "stored_name"), ("auditLabel", "stored_label")]);
    assert_eq!(
        project(&fields, model.record_fields(&fields)?).await?,
        json!([{
            "id":"organization", "name":"after", "slug":"slug", "logo":null, "metadata":null,
            "createdAt":NOW, "authUpdatedAt":NOW, "auditLabel":"stored_label",
        }])
    );
    Ok(())
}
