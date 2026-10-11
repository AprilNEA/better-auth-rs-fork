use better_auth_seaorm::{OrganizationModels, SeaOrmOrganizationSchema};

#[expect(
    unreachable_pub,
    reason = "SeaORM derives require public fixture entity types"
)]
pub(super) mod team {
    use better_auth_seaorm::sea_orm::{self, entity::prelude::*};

    #[derive(
        Clone, Debug, PartialEq, serde::Serialize, DeriveEntityModel, better_auth_seaorm::AuthEntity,
    )]
    #[auth(role = "team")]
    #[sea_orm(table_name = "team")]
    pub struct Model {
        #[sea_orm(primary_key, auto_increment = false)]
        pub id: String,
        pub name: String,
        pub organization_id: String,
        pub created_at: DateTimeUtc,
        pub updated_at: Option<DateTimeUtc>,
        pub member_count: i64,
        #[sea_orm(column_name = "_joined_team_member_team_id")]
        #[serde(rename = "_joined_team_member_team_id")]
        pub join_shadow: Option<String>,
        #[sea_orm(column_name = "_JoinedTeam_memberTeam_id")]
        #[serde(rename = "_JoinedTeam_memberTeam_id")]
        pub alternate_join_shadow: Option<String>,
    }

    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}
    impl ActiveModelBehavior for ActiveModel {}
}

pub(super) type Models = OrganizationModels<
    <OrganizationModels as SeaOrmOrganizationSchema>::Organization,
    <OrganizationModels as SeaOrmOrganizationSchema>::Member,
    <OrganizationModels as SeaOrmOrganizationSchema>::Invitation,
    team::Model,
>;
