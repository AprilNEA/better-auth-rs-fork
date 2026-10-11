#[expect(
    unreachable_pub,
    reason = "SeaORM derives require public fixture entity types."
)]
pub(super) mod organization {
    use better_auth_seaorm::sea_orm::{self, entity::prelude::*};

    #[derive(
        Clone, Debug, PartialEq, serde::Serialize, DeriveEntityModel, better_auth_seaorm::AuthEntity,
    )]
    #[auth(role = "organization")]
    #[sea_orm(table_name = "organization")]
    #[serde(rename_all = "camelCase")]
    pub struct Model {
        #[sea_orm(primary_key, auto_increment = false)]
        pub id: String,
        pub name: String,
        pub slug: String,
        pub logo: Option<String>,
        pub metadata: Option<String>,
        #[sea_orm(column_name = "createdAt")]
        pub created_at: DateTimeUtc,
        pub invitation: Option<String>,
        pub member: Option<String>,
        pub stored_invitation: Option<String>,
        pub stored_member: Option<String>,
        pub lookup: Option<String>,
        pub stored_lookup: Option<String>,
    }

    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}
    impl ActiveModelBehavior for ActiveModel {}
}

#[expect(
    unreachable_pub,
    reason = "SeaORM derives require public fixture entity types."
)]
pub(super) mod member {
    use better_auth_seaorm::sea_orm::{self, entity::prelude::*};

    #[derive(
        Clone, Debug, PartialEq, serde::Serialize, DeriveEntityModel, better_auth_seaorm::AuthEntity,
    )]
    #[auth(role = "member")]
    #[sea_orm(table_name = "member")]
    #[serde(rename_all = "camelCase")]
    pub struct Model {
        #[sea_orm(primary_key, auto_increment = false)]
        pub id: String,
        #[sea_orm(column_name = "organizationId")]
        pub organization_id: String,
        #[sea_orm(column_name = "userId")]
        pub user_id: String,
        pub role: String,
        #[sea_orm(column_name = "createdAt")]
        pub created_at: DateTimeUtc,
        pub lookup: Option<String>,
        pub stored_lookup: Option<String>,
    }

    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}
    impl ActiveModelBehavior for ActiveModel {}
}

#[expect(
    unreachable_pub,
    reason = "SeaORM derives require public fixture entity types."
)]
pub(super) mod invitation {
    use better_auth_seaorm::sea_orm::{self, entity::prelude::*};

    #[derive(
        Clone, Debug, PartialEq, serde::Serialize, DeriveEntityModel, better_auth_seaorm::AuthEntity,
    )]
    #[auth(role = "invitation")]
    #[sea_orm(table_name = "invitation")]
    #[serde(rename_all = "camelCase")]
    pub struct Model {
        #[sea_orm(primary_key, auto_increment = false)]
        pub id: String,
        #[sea_orm(column_name = "organizationId")]
        pub organization_id: String,
        pub email: String,
        pub role: String,
        #[sea_orm(column_name = "teamId")]
        pub team_id: Option<String>,
        pub status: String,
        #[sea_orm(column_name = "inviterId")]
        pub inviter_id: String,
        #[sea_orm(column_name = "createdAt")]
        pub created_at: DateTimeUtc,
        #[sea_orm(column_name = "expiresAt")]
        pub expires_at: DateTimeUtc,
    }

    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}
    impl ActiveModelBehavior for ActiveModel {}
}

#[expect(
    unreachable_pub,
    reason = "SeaORM derives require public fixture entity types."
)]
pub(super) mod team {
    use better_auth_seaorm::sea_orm::{self, entity::prelude::*};

    #[derive(
        Clone, Debug, PartialEq, serde::Serialize, DeriveEntityModel, better_auth_seaorm::AuthEntity,
    )]
    #[auth(role = "team")]
    #[sea_orm(table_name = "team")]
    #[serde(rename_all = "camelCase")]
    pub struct Model {
        #[sea_orm(primary_key, auto_increment = false)]
        pub id: String,
        #[sea_orm(column_name = "organizationId")]
        pub organization_id: String,
        pub name: String,
        #[sea_orm(column_name = "memberCount")]
        pub member_count: i64,
        #[sea_orm(column_name = "createdAt")]
        pub created_at: DateTimeUtc,
        #[sea_orm(column_name = "updatedAt")]
        pub updated_at: Option<DateTimeUtc>,
    }

    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}
    impl ActiveModelBehavior for ActiveModel {}
}

pub(super) type Organizations = better_auth_seaorm::OrganizationModels<
    organization::Model,
    member::Model,
    invitation::Model,
    team::Model,
>;
