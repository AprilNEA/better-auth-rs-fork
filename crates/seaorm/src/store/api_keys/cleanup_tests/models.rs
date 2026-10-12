macro_rules! api_key_model {
    ($module:ident, $id:ty, $expiry:ty, $expiry_type:literal) => {
        #[expect(
            unreachable_pub,
            reason = "SeaORM derives require public fixture entity types."
        )]
        pub(super) mod $module {
            use sea_orm::entity::prelude::*;

            #[derive(Clone, Debug, PartialEq, DeriveEntityModel, crate::AuthEntity)]
            #[auth(role = "api_key")]
            #[sea_orm(table_name = "apikey")]
            pub struct Model {
                #[sea_orm(primary_key, auto_increment = false)]
                pub id: $id,
                #[sea_orm(column_name = "configId")]
                pub config_id: String,
                pub name: Option<String>,
                pub start: Option<String>,
                #[sea_orm(column_name = "referenceId")]
                pub reference_id: String,
                pub prefix: Option<String>,
                #[sea_orm(column_name = "key")]
                pub key_hash: String,
                #[sea_orm(column_name = "refillInterval", column_type = "Integer", nullable)]
                pub refill_interval: Option<crate::SqlNumber>,
                #[sea_orm(column_name = "refillAmount", column_type = "Integer", nullable)]
                pub refill_amount: Option<crate::SqlNumber>,
                #[sea_orm(column_name = "lastRefillAt")]
                pub last_refill_at: Option<DateTimeUtc>,
                pub enabled: Option<bool>,
                #[sea_orm(column_name = "rateLimitEnabled")]
                pub rate_limit_enabled: Option<bool>,
                #[sea_orm(column_name = "rateLimitTimeWindow", column_type = "Integer", nullable)]
                pub rate_limit_time_window: Option<crate::SqlNumber>,
                #[sea_orm(column_name = "rateLimitMax", column_type = "Integer", nullable)]
                pub rate_limit_max: Option<crate::SqlNumber>,
                #[sea_orm(column_name = "requestCount", column_type = "Integer", nullable)]
                pub request_count: Option<crate::SqlNumber>,
                #[sea_orm(column_type = "Integer", nullable)]
                pub remaining: Option<crate::SqlNumber>,
                #[sea_orm(column_name = "lastRequest")]
                pub last_request: Option<DateTimeUtc>,
                #[sea_orm(column_name = "stored_expiry", column_type = $expiry_type, nullable)]
                pub expires_at: Option<$expiry>,
                #[sea_orm(column_name = "createdAt")]
                pub created_at: DateTimeUtc,
                #[sea_orm(column_name = "updatedAt")]
                pub updated_at: DateTimeUtc,
                pub permissions: Option<String>,
                pub metadata: Option<Json>,
            }

            #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
            pub enum Relation {}
            impl ActiveModelBehavior for ActiveModel {}
        }
    };
}

api_key_model!(date, String, DateTimeUtc, "TimestampWithTimeZone");
api_key_model!(sqlite_json, String, String, "Text");
api_key_model!(native_json, String, Json, "JsonBinary");
api_key_model!(serial, i32, crate::SqlNumber, "Integer");

#[expect(
    unreachable_pub,
    reason = "SeaORM derives require public fixture entity types."
)]
pub(super) mod user {
    use sea_orm::entity::prelude::*;

    #[derive(Clone, Debug, PartialEq, serde::Serialize, DeriveEntityModel, crate::AuthEntity)]
    #[auth(role = "user")]
    #[sea_orm(table_name = "user")]
    pub struct Model {
        #[sea_orm(primary_key, auto_increment = false)]
        pub id: i32,
        pub name: Option<String>,
        pub email: String,
        #[sea_orm(column_name = "emailVerified")]
        pub email_verified: bool,
        pub image: Option<String>,
        #[sea_orm(column_name = "createdAt")]
        pub created_at: DateTimeUtc,
        #[sea_orm(column_name = "updatedAt")]
        pub updated_at: DateTimeUtc,
    }

    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}
    impl ActiveModelBehavior for ActiveModel {}
}

pub(super) struct CoreSchema;

impl better_auth_core::AuthSchema for CoreSchema {
    type User = user::Model;
    type Session = crate::store::entities::session::Model;
    type Account = crate::store::entities::account::Model;
    type Verification = crate::store::entities::verification::Model;
}
