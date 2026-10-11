use super::{
    SeaOrmStore, map_db_err,
    organization_models::{self as models, Entity},
};
use crate::schema::AuthSchema;
use crate::{
    SeaOrmOrganizationModel, SeaOrmOrganizationSchema, SeaOrmPluginSchema, SeaOrmUserModel,
};
use better_auth_core::{
    AuthError, AuthResult,
    store::{MemberUser, OrganizationDetails, OrganizationDetailsQuery, OrganizationKey},
    user_fields::UserConfig,
};
use sea_orm::{EntityTrait, IdenStatic, QueryFilter, QuerySelect, Value};

mod native;

async fn project_sequential<M: SeaOrmOrganizationModel>(
    rows: Vec<M>,
    config: &UserConfig,
    backend: sea_orm::DbBackend,
    runtime: (
        &better_auth_core::plugin_runtime::ModelFields,
        better_auth_core::store::schema::EntityRole,
    ),
) -> AuthResult<Vec<M::Record>> {
    let mut result = Vec::with_capacity(rows.len());
    for row in rows {
        result.push(models::record(&row, config, backend, runtime).await?);
    }
    Ok(result)
}

impl<S: AuthSchema, O: SeaOrmOrganizationSchema, P: SeaOrmPluginSchema> SeaOrmStore<S, O, P>
where
    S::User: SeaOrmUserModel,
    S::Session: crate::SeaOrmSessionModel,
    S::Account: crate::SeaOrmAccountModel,
    S::Verification: crate::SeaOrmVerificationModel,
{
    pub(super) async fn read_organization_details(
        &self,
        input: OrganizationDetailsQuery<'_>,
    ) -> AuthResult<Option<OrganizationDetails>> {
        if self.config().advanced.database.joins == Some(true) {
            return self.read_native_organization_details(input).await;
        }
        let fields = self.organization_fields()?;
        let backend = self.connection().get_database_backend();
        let predicate = match input.organization {
            OrganizationKey::Id(id) => self.organization_field_equals::<O::Organization>(
                better_auth_core::store::schema::EntityRole::Organization,
                "id",
                &id.into(),
            )?,
            OrganizationKey::IdValue(id) => self.organization_field_equals::<O::Organization>(
                better_auth_core::store::schema::EntityRole::Organization,
                "id",
                id,
            )?,
            OrganizationKey::Slug(slug) => self.organization_field_equals::<O::Organization>(
                better_auth_core::store::schema::EntityRole::Organization,
                "slug",
                &slug.into(),
            )?,
        };
        let query = Entity::<O::Organization>::find().filter(predicate).limit(1);
        let member_limit = input
            .members_limit
            .unwrap_or(self.config().advanced.database.find_many_limit());
        let Some(organization) = query.one(self.connection()).await.map_err(map_db_err)? else {
            return Ok(None);
        };
        let organization_id = models::join_value(&organization, "id")?;
        let organization = models::record(
            &organization,
            &fields.organization,
            backend,
            (
                &self.model_fields,
                better_auth_core::store::schema::EntityRole::Organization,
            ),
        )
        .await?;
        let (invitations, members, teams) = {
            let limit = super::pagination::default_limit(
                self.config(),
                self.connection().get_database_backend(),
            )?;
            self.model_fields
                .begin_id_query(better_auth_core::store::schema::EntityRole::Invitation)?;
            let rows = Entity::<O::Invitation>::find()
                .filter(super::value_filter::equals_native(
                    O::Invitation::column("organization_id")?,
                    organization_id.clone(),
                    backend,
                )?)
                .limit(limit)
                .all(self.connection())
                .await
                .map_err(map_db_err)?;
            let invitations = project_sequential(
                rows,
                &fields.invitation,
                backend,
                (
                    &self.model_fields,
                    better_auth_core::store::schema::EntityRole::Invitation,
                ),
            )
            .await?;
            let (member_limit, _) = super::pagination::sql_pagination(
                self.connection().get_database_backend(),
                Some(member_limit),
                None,
            )?;
            self.model_fields
                .begin_id_query(better_auth_core::store::schema::EntityRole::Member)?;
            let rows = Entity::<O::Member>::find()
                .filter(super::value_filter::equals_native(
                    O::Member::column("organization_id")?,
                    organization_id.clone(),
                    backend,
                )?)
                .limit(member_limit)
                .all(self.connection())
                .await
                .map_err(map_db_err)?;
            let members = self
                .project_members_with_owners(rows, &fields.member, backend)
                .await?;
            let teams = if input.include_teams {
                self.model_fields
                    .begin_id_query(better_auth_core::store::schema::EntityRole::Team)?;
                let rows = Entity::<O::Team>::find()
                    .filter(super::value_filter::equals_native(
                        O::Team::column("organization_id")?,
                        organization_id,
                        backend,
                    )?)
                    .limit(limit)
                    .all(self.connection())
                    .await
                    .map_err(map_db_err)?;
                Some(
                    project_sequential(
                        rows,
                        &fields.team,
                        backend,
                        (
                            &self.model_fields,
                            better_auth_core::store::schema::EntityRole::Team,
                        ),
                    )
                    .await?,
                )
            } else {
                None
            };
            (invitations, members, teams)
        };
        let user_rows = if members.is_empty() {
            Vec::new()
        } else {
            self.model_fields
                .begin_id_query(better_auth_core::store::schema::EntityRole::User)?;
            let (limit, _) = super::pagination::sql_pagination(
                self.connection().get_database_backend(),
                Some(input.users_limit),
                None,
            )?;
            super::plugin_rows::all(
                self.connection(),
                <S::User as SeaOrmUserModel>::Entity::find()
                    .filter(super::value_filter::is_in_native(
                        S::User::id_column(),
                        members.iter().map(|(_, owner)| owner.clone()),
                        backend,
                    )?)
                    .limit(limit),
            )
            .await?
        };
        let ids = user_rows
            .iter()
            .map(|user| user.value(S::User::id_column().as_str())?.display_utf16())
            .collect::<AuthResult<Vec<_>>>()?;
        let users = self.output_users(&user_rows, self.connection()).await?;
        let members = members
            .into_iter()
            .map(|(member, owner)| {
                let owner = crate::__private_field_value(owner)?.display_utf16()?;
                let index = ids.iter().position(|id| *id == owner).ok_or_else(|| {
                    AuthError::internal("Unexpected error: User not found for member")
                })?;
                Ok(MemberUser {
                    member,
                    user: better_auth_core::MemberUserView::from_user(
                        users.get(index).ok_or_else(|| {
                            AuthError::internal("Member projection lost its stored user index")
                        })?,
                    ),
                })
            })
            .collect::<AuthResult<Vec<_>>>()?;
        Ok(Some(OrganizationDetails {
            organization,
            invitations,
            members,
            teams,
        }))
    }

    async fn project_members_with_owners(
        &self,
        rows: Vec<O::Member>,
        fields: &UserConfig,
        backend: sea_orm::DbBackend,
    ) -> AuthResult<Vec<(better_auth_core::Member, Value)>> {
        let mut members = Vec::with_capacity(rows.len());
        for row in rows {
            let owner = models::join_value(&row, "user_id")?;
            members.push((
                models::record(
                    &row,
                    fields,
                    backend,
                    (
                        &self.model_fields,
                        better_auth_core::store::schema::EntityRole::Member,
                    ),
                )
                .await?,
                owner,
            ));
        }
        Ok(members)
    }
}
