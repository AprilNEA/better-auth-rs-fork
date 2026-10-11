use crate::{
    SeaOrmAccountModel, SeaOrmOrganizationModel, SeaOrmPluginModel, SeaOrmSessionModel,
    SeaOrmUserModel, SeaOrmVerificationModel,
};
use better_auth_core::{
    AuthResult, AuthSchema, FieldMap,
    organization_fields::OrganizationFields,
    plugin_runtime::ModelFields,
    store::schema::{EntityRole, SchemaConfiguration, SchemaTable, resolve_field_name},
    user_fields::UserConfig,
};
use sea_orm::{ColumnTrait, EntityTrait};

fn model<E: EntityTrait>(columns: Vec<String>) -> SchemaTable {
    let entity = E::default();
    SchemaTable {
        name: entity.table_name().to_owned(),
        schema: entity.schema_name().map(str::to_owned),
        columns,
        disable_migrations: false,
    }
}

fn columns<C: ColumnTrait>(
    fields: &UserConfig,
    column: impl Fn(&str) -> AuthResult<C>,
    extra_insert_columns: impl IntoIterator<Item = C>,
) -> AuthResult<Vec<String>> {
    let mut names = vec![column("id")?.as_str().to_owned()];
    for (logical, field) in fields.fields() {
        let name = column(resolve_field_name(field.field_name.as_deref(), logical))?
            .as_str()
            .to_owned();
        if !names.contains(&name) {
            names.push(name);
        }
    }
    for column in extra_insert_columns {
        let name = column.as_str().to_owned();
        if !names.contains(&name) {
            names.push(name);
        }
    }
    Ok(names)
}

fn organization<M: SeaOrmOrganizationModel>(
    fields: &UserConfig,
    extra_insert_columns: impl IntoIterator<Item = M::Column>,
) -> AuthResult<SchemaTable> {
    Ok(model::<M::Entity>(columns(
        fields,
        M::column,
        extra_insert_columns,
    )?))
}

fn plugin<M: SeaOrmPluginModel>(role: EntityRole, fields: &UserConfig) -> AuthResult<SchemaTable> {
    let legacy = match role {
        EntityRole::Passkey if M::passkey_storage() == better_auth_core::PasskeyStorage::Legacy => {
            &[("credential", "credential"), ("updatedAt", "updated_at")][..]
        }
        EntityRole::TwoFactor
            if M::two_factor_storage() == better_auth_core::TwoFactorStorage::Legacy =>
        {
            &[("createdAt", "created_at"), ("updatedAt", "updated_at")][..]
        }
        _ => &[],
    };
    let extra_insert_columns = legacy
        .iter()
        .filter(|(logical, _)| !fields.fields().contains_key(*logical))
        .map(|(_, physical)| M::column(physical))
        .collect::<AuthResult<Vec<_>>>()?;
    Ok(model::<M::Entity>(columns(
        fields,
        M::column,
        extra_insert_columns,
    )?))
}

pub(super) fn tables<S, O, P>(
    settings: &SchemaConfiguration,
    organization_fields: &OrganizationFields,
    model_fields: &ModelFields,
) -> AuthResult<Vec<SchemaTable>>
where
    S: AuthSchema,
    S::User: SeaOrmUserModel,
    S::Session: SeaOrmSessionModel,
    S::Account: SeaOrmAccountModel,
    S::Verification: SeaOrmVerificationModel,
    O: crate::SeaOrmOrganizationSchema,
    P: crate::SeaOrmPluginSchema,
{
    let config = &settings.config;
    settings
        .models()
        .into_iter()
        .map(|(role, _)| match role {
            EntityRole::User => Ok(model::<<S::User as SeaOrmUserModel>::Entity>(columns(
                &config
                    .user
                    .user_field_schema_with_plugins(model_fields.user_plugin_fields()),
                S::User::field_column,
                [],
            )?)),
            EntityRole::Session => Ok(model::<<S::Session as SeaOrmSessionModel>::Entity>(
                columns(
                    &better_auth_core::store::session_field_schema(
                        &config.session,
                        &FieldMap::new(),
                    ),
                    S::Session::field_column,
                    S::Session::extra_insert_columns()
                        .into_iter()
                        .chain(S::Session::active_column()),
                )?,
            )),
            EntityRole::Account => Ok(model::<<S::Account as SeaOrmAccountModel>::Entity>(
                columns(
                    &config.account.field_schema(),
                    S::Account::field_column,
                    S::Account::extra_insert_columns(),
                )?,
            )),
            EntityRole::Verification => Ok(model::<
                <S::Verification as SeaOrmVerificationModel>::Entity,
            >(columns(
                &config.verification.field_schema(),
                S::Verification::field_column,
                S::Verification::extra_insert_columns(),
            )?)),
            EntityRole::Organization => {
                let fields = organization_fields.schema_for(role)?;
                let updated_at = O::Organization::column("auth_updated_at")?;
                let logical =
                    O::Organization::core_field_name(&updated_at).unwrap_or("auth_updated_at");
                let extra = (!fields.fields().contains_key(logical)).then_some(updated_at);
                organization::<O::Organization>(&fields, extra)
            }
            EntityRole::Member => {
                organization::<O::Member>(&organization_fields.schema_for(role)?, [])
            }
            EntityRole::Invitation => {
                organization::<O::Invitation>(&organization_fields.schema_for(role)?, [])
            }
            EntityRole::Team => organization::<O::Team>(&organization_fields.schema_for(role)?, []),
            EntityRole::TeamMember => {
                organization::<O::TeamMember>(&model_fields.plugin_fields(role), [])
            }
            EntityRole::OrganizationRole => {
                organization::<O::OrganizationRole>(&organization_fields.schema_for(role)?, [])
            }
            EntityRole::ApiKey => plugin::<P::ApiKey>(role, &model_fields.plugin_fields(role)),
            EntityRole::DeviceCode => {
                plugin::<P::DeviceCode>(role, &model_fields.plugin_fields(role))
            }
            EntityRole::Passkey => plugin::<P::Passkey>(role, &model_fields.plugin_fields(role)),
            EntityRole::TwoFactor => {
                plugin::<P::TwoFactor>(role, &model_fields.plugin_fields(role))
            }
            EntityRole::Jwk => plugin::<P::Jwk>(role, &model_fields.plugin_fields(role)),
            EntityRole::WalletAddress => {
                plugin::<P::WalletAddress>(role, &model_fields.plugin_fields(role))
            }
            // RateLimit's atomic writer binds native columns directly without field policies.
            EntityRole::RateLimit => {
                plugin::<P::RateLimit>(role, &ModelFields::plugin_native_fields(role))
            }
        })
        .collect()
}
