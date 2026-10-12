use crate::{
    SeaOrmAccountModel, SeaOrmOrganizationModel, SeaOrmPluginModel, SeaOrmSessionModel,
    SeaOrmUserModel, SeaOrmVerificationModel,
};
use better_auth_core::{
    AuthResult, AuthSchema, FieldMap,
    organization_fields::OrganizationFields,
    plugin_runtime::ModelFields,
    store::schema::{
        EntityRole, SchemaConfiguration, SchemaTable, core_fields, resolve_field_name,
    },
    user_fields::UserConfig,
};
use sea_orm::{ColumnTrait, EntityTrait};

fn model<E: EntityTrait>((id_column, columns): (String, Vec<String>)) -> SchemaTable {
    let entity = E::default();
    SchemaTable {
        name: entity.table_name().to_owned(),
        schema: entity.schema_name().map(str::to_owned),
        id_column,
        columns,
        disable_migrations: false,
    }
}

fn columns<C: ColumnTrait>(
    fields: &UserConfig,
    column: impl Fn(&str) -> AuthResult<C>,
    extra_insert_columns: impl IntoIterator<Item = C>,
) -> AuthResult<(String, Vec<String>)> {
    let id_column = column("id")?.as_str().to_owned();
    let mut names = Vec::new();
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
    Ok((id_column, names))
}

fn organization<M: SeaOrmOrganizationModel>(
    role: EntityRole,
    fields: &UserConfig,
) -> AuthResult<SchemaTable> {
    let extra_insert_columns = core_fields(role)
        .iter()
        .filter_map(|field| field.adapter_private.map(|logical| (field, logical)))
        .filter_map(|(field, logical)| {
            super::super::organization_models::private_column::<M>(fields, field.name, logical)
                .transpose()
        })
        .collect::<AuthResult<Vec<_>>>()?;
    Ok(model::<M::Entity>(columns(
        fields,
        M::column,
        extra_insert_columns,
    )?))
}

fn plugin<M: SeaOrmPluginModel>(role: EntityRole, fields: &UserConfig) -> AuthResult<SchemaTable> {
    let legacy = match role {
        EntityRole::Passkey => M::passkey_storage() == better_auth_core::PasskeyStorage::Legacy,
        EntityRole::TwoFactor => {
            M::two_factor_storage() == better_auth_core::TwoFactorStorage::Legacy
        }
        _ => false,
    };
    let extra_insert_columns = core_fields(role)
        .iter()
        .filter(|_| legacy)
        .filter_map(|field| field.adapter_private)
        .filter_map(|logical| {
            super::super::plugin_rows::private_column::<M>(fields, logical).transpose()
        })
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
    model_fields
        .active_models()
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
                organization::<O::Organization>(role, organization_fields.fields_for(role)?)
            }
            EntityRole::Member => {
                organization::<O::Member>(role, organization_fields.fields_for(role)?)
            }
            EntityRole::Invitation => {
                organization::<O::Invitation>(role, organization_fields.fields_for(role)?)
            }
            EntityRole::Team => {
                organization::<O::Team>(role, organization_fields.fields_for(role)?)
            }
            EntityRole::TeamMember => {
                organization::<O::TeamMember>(role, &model_fields.plugin_fields(role))
            }
            EntityRole::OrganizationRole => {
                organization::<O::OrganizationRole>(role, organization_fields.fields_for(role)?)
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
            EntityRole::RateLimit => {
                plugin::<P::RateLimit>(role, &model_fields.plugin_fields(role))
            }
        })
        .collect()
}
