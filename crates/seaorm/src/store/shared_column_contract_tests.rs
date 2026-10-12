//! Replay bare SQLite adapter operations through the production record engine.

use super::{Entity, SeaOrmStore, map_db_err};
use crate::{SeaOrmPluginModel, store::bundled_schema::BundledSchema};
use better_auth_core as auth_core;
use better_auth_core::{
    AuthConfig, AuthError, AuthResult, FieldMap, FieldValue, store::schema::EntityRole,
};
use sea_orm::sqlx::{Column, Row};
use sea_orm::{ConnectionTrait, Database, DatabaseConnection, QueryOrder, QueryTrait};
use serde_json::Value;
use std::marker::PhantomData;

#[path = "../../../../tests/support/shared_column_contract.rs"]
mod contract;

// The record engine reads raw driver values; these entities supply only physical table and column metadata.
// Runtime declarations select the actual model role. Generated model types have a separate consumer contract.
macro_rules! sql_model {
    ($module:ident, $table:literal, $( $field:ident => $column:literal ),* $(,)?) => {
        #[expect(unreachable_pub, reason = "SeaORM derives require public fixture entity types")]
        mod $module {
            use sea_orm::entity::prelude::*;

            #[derive(Clone, Debug, DeriveEntityModel, crate::AuthEntity)]
            #[sea_orm(table_name = $table)]
            #[auth(role = "jwk")]
            pub struct Model {
                #[sea_orm(primary_key, auto_increment = false)]
                pub id: String,
                #[sea_orm(column_name = "shared_value")]
                pub shared_value: Option<String>,
                $(
                    #[sea_orm(column_name = $column)]
                    pub $field: Option<String>,
                )*
            }

            #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
            pub enum Relation {}
            impl ActiveModelBehavior for ActiveModel {}
        }
    };
}

sql_model!(user, "user",
    email => "email", email_verified => "emailVerified", image => "image",
    created_at => "createdAt", updated_at => "updatedAt",
);
sql_model!(session, "session",
    expires_at => "expiresAt", token => "token", created_at => "createdAt",
    updated_at => "updatedAt", user_agent => "userAgent", user_id => "userId",
    active_organization_id => "activeOrganizationId", active_team_id => "activeTeamId",
);
sql_model!(account, "account",
    provider_id => "providerId", user_id => "userId", access_token => "accessToken",
    refresh_token => "refreshToken", id_token => "idToken",
    access_token_expires_at => "accessTokenExpiresAt", refresh_token_expires_at => "refreshTokenExpiresAt",
    scope => "scope", password => "password", created_at => "createdAt", updated_at => "updatedAt",
);
sql_model!(verification, "verification",
    value => "value", expires_at => "expiresAt", created_at => "createdAt", updated_at => "updatedAt",
);
sql_model!(organization, "organization",
    slug => "slug", logo => "logo", created_at => "createdAt", metadata => "metadata",
);
sql_model!(member, "member",
    organization_id => "organizationId", user_id => "userId", created_at => "createdAt",
);
sql_model!(invitation, "invitation",
    organization_id => "organizationId", email => "email", role => "role", team_id => "teamId",
    expires_at => "expiresAt", created_at => "createdAt", inviter_id => "inviterId",
);
sql_model!(team, "team",
    organization_id => "organizationId", member_count => "memberCount",
    created_at => "createdAt", updated_at => "updatedAt",
);
sql_model!(team_member, "teamMember",
    user_id => "userId", membership_key => "membershipKey", created_at => "createdAt",
);
sql_model!(organization_role, "organizationRole",
    organization_id => "organizationId", permission => "permission",
    created_at => "createdAt", updated_at => "updatedAt",
);

struct Adapter<M> {
    store: SeaOrmStore<BundledSchema>,
    role: EntityRole,
    model: String,
    metadata: PhantomData<fn() -> M>,
}

#[auth_core::__private_async_trait::async_trait]
impl<M: SeaOrmPluginModel> contract::Adapter for Adapter<M> {
    async fn execute(&self, method: &str, input: FieldMap) -> AuthResult<FieldValue> {
        assert_eq!(input.get("model"), Some(&self.model.clone().into()));
        let connection = self.store.connection();
        match method {
            "create" => {
                assert_eq!(input.get("forceAllowId"), Some(&true.into()));
                self.store
                    .create_plugin_record::<M>(
                        connection,
                        crate::store::create_readback::ReadbackScope::Direct(connection),
                        self.role,
                        &self.model,
                        contract::parameter(&input, "data")?,
                    )
                    .await
                    .map(|row| row.map_or(FieldValue::Null, Into::into))
            }
            "findOne" => self
                .store
                .get_plugin_record::<M>(connection, self.role, &contract::identifier(&input)?)
                .await
                .map(|row| row.map_or(FieldValue::Null, Into::into)),
            "update" => self
                .store
                .update_plugin_record::<M>(
                    connection,
                    self.role,
                    &self.model,
                    &contract::identifier(&input)?,
                    contract::parameter(&input, "update")?,
                )
                .await
                .map(|row| row.map_or(FieldValue::Null, Into::into)),
            "delete" => {
                self.store
                    .delete_plugin_record::<M>(
                        connection,
                        self.role,
                        &contract::identifier(&input)?,
                    )
                    .await?;
                Ok(FieldValue::Undefined)
            }
            _ => Err(AuthError::internal("Unknown captured adapter method")),
        }
    }

    async fn stored(&self) -> AuthResult<Vec<FieldMap>> {
        let connection = self.store.connection();
        let rows = connection
            .query_all_raw(
                crate::store::plugin_rows::select_all::<Entity<M>>()
                    .order_by_asc(M::column("id")?)
                    .build(connection.get_database_backend()),
            )
            .await
            .map_err(map_db_err)?;
        rows.into_iter()
            .map(|row| {
                let sqlite = row.try_as_sqlite_row().ok_or_else(|| {
                    AuthError::internal("The shared-column contract requires SQLite driver rows")
                })?;
                sqlite
                    .columns()
                    .iter()
                    .map(|column| {
                        Ok((
                            column.name().to_owned(),
                            crate::store::plugin_rows::value(&row, column.name())?,
                        ))
                    })
                    .collect()
            })
            .collect()
    }
}

async fn database(case: &Value, model: &str) -> AuthResult<DatabaseConnection> {
    let database = Database::connect("sqlite::memory:")
        .await
        .map_err(map_db_err)?;
    // Parent records supply the capture's referenced IDs; only the target table belongs to this contract.
    for (parent, id) in [
        ("user", "owner"),
        ("organization", "workspace"),
        ("team", "team"),
    ] {
        if parent != model {
            let _ = database
                .execute_unprepared(&format!("CREATE TABLE \"{parent}\" (id TEXT PRIMARY KEY)"))
                .await
                .map_err(map_db_err)?;
            let _ = database
                .execute_unprepared(&format!("INSERT INTO \"{parent}\" (id) VALUES ('{id}')"))
                .await
                .map_err(map_db_err)?;
        }
    }
    let declarations = case["catalog"]["ddl"]
        .as_array()
        .ok_or_else(|| AuthError::internal("Missing captured SQLite DDL"))?;
    for kind in ["table", "index"] {
        for declaration in declarations
            .iter()
            .filter(|declaration| declaration["type"] == kind)
        {
            if let Some(sql) = declaration["sql"].as_str() {
                let _ = database.execute_unprepared(sql).await.map_err(map_db_err)?;
            }
        }
    }
    Ok(database)
}

async fn replay<M: SeaOrmPluginModel>(case: &Value) -> AuthResult<()> {
    let (runtime, role, trace) = contract::runtime(case)?;
    let model = case["model"]
        .as_str()
        .ok_or_else(|| AuthError::internal("Missing captured SQL model"))?;
    let mut store =
        SeaOrmStore::<BundledSchema>::new(AuthConfig::default(), database(case, model).await?);
    store.model_fields = runtime;
    contract::run(
        &Adapter::<M> {
            store,
            role,
            model: model.to_owned(),
            metadata: PhantomData,
        },
        case,
        &trace,
    )
    .await
}

#[tokio::test]
async fn shared_record_crud_matches_all_pinned_sqlite_column_collisions() -> AuthResult<()> {
    for case in contract::cases("sqlite")? {
        match case["model"].as_str() {
            Some("user") => replay::<user::Model>(&case).await?,
            Some("session") => replay::<session::Model>(&case).await?,
            Some("account") => replay::<account::Model>(&case).await?,
            Some("verification") => replay::<verification::Model>(&case).await?,
            Some("organization") => replay::<organization::Model>(&case).await?,
            Some("member") => replay::<member::Model>(&case).await?,
            Some("invitation") => replay::<invitation::Model>(&case).await?,
            Some("team") => replay::<team::Model>(&case).await?,
            Some("teamMember") => replay::<team_member::Model>(&case).await?,
            Some("organizationRole") => replay::<organization_role::Model>(&case).await?,
            _ => return Err(AuthError::internal("Unknown captured SQL model")),
        }
    }
    Ok(())
}
