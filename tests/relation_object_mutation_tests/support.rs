use super::*;

pub(super) enum Storage {
    Memory(Arc<EphemeralStore>),
    Sqlite {
        database: DatabaseConnection,
        children: Vec<FieldMap>,
    },
}

impl Storage {
    pub(super) fn is_memory(&self) -> bool {
        matches!(self, Self::Memory(_))
    }

    pub(super) async fn rows(&self, role: EntityRole) -> TestResult<Vec<FieldMap>> {
        match self {
            Self::Memory(store) => Ok(store.storage_rows(role)?),
            Self::Sqlite { database, .. } => {
                let table = match role {
                    EntityRole::User => "linked_user",
                    EntityRole::Account => "linked_account",
                    EntityRole::Team => "linked_team",
                    EntityRole::TeamMember => "linked_team_member",
                    _ => return Err("Unexpected relation storage role".into()),
                };
                let names = database
                    .query_all_raw(Statement::from_string(
                        DbBackend::Sqlite,
                        format!("PRAGMA table_info(\"{table}\")"),
                    ))
                    .await?
                    .into_iter()
                    .map(|row| row.try_get::<String>("", "name"))
                    .collect::<Result<Vec<_>, _>>()?;
                let columns = names
                    .iter()
                    .map(|name| format!("'{name}',\"{name}\""))
                    .collect::<Vec<_>>()
                    .join(",");
                database
                    .query_all_raw(Statement::from_string(
                        DbBackend::Sqlite,
                        format!(
                            "SELECT json_object({columns}) AS value FROM \"{table}\" ORDER BY rowid"
                        ),
                    ))
                    .await?
                    .into_iter()
                    .map(|row| {
                        let json: serde_json::Value =
                            serde_json::from_str(&row.try_get::<String>("", "value")?)?;
                        Ok(FieldValue::from_json(json)?
                            .as_object()
                            .ok_or("Expected stored object")?
                            .snapshot_fields()?)
                    })
                    .collect()
            }
        }
    }
}

pub(super) fn configured<S: AuthSchema>(
    raw: &(impl RuntimeStore<S> + ?Sized),
    target: Target,
    joins: bool,
    parent: Option<UserConfig>,
    child: UserConfig,
) -> AuthResult<Arc<dyn AuthStore<S>>> {
    let mut config =
        AuthConfig::new("relation-object-mutation-secret-at-least-thirty-two-characters");
    config.advanced.database.joins = Some(joins);
    let parent = parent.unwrap_or_else(|| UserConfig {
        additional_fields: Some(
            [
                (target.physical().into(), UserFieldConfig::default()),
                (
                    "relationMirror".into(),
                    UserFieldConfig {
                        field_name: Some(target.physical().into()),
                        ..Default::default()
                    },
                ),
            ]
            .into(),
        ),
    });
    let mut organization = None;
    match target {
        Target::User => {
            config.user = parent;
            config.account.additional_fields = child.additional_fields.unwrap_or_default();
        }
        Target::Account => {
            config.account.additional_fields = parent.additional_fields.unwrap_or_default();
            config.user = child;
        }
        Target::Team => {
            organization = Some((
                OrganizationFields {
                    team: parent,
                    ..Default::default()
                },
                child,
            ));
        }
    }
    let config = Arc::new(config);

    let mut model_fields = ModelFields::default();
    model_fields.register_model_schema(
        EntityRole::User,
        Some("linked_user"),
        UserConfig::default(),
    )?;
    model_fields.register_model_schema(
        EntityRole::Account,
        Some("linked_account"),
        UserConfig::default(),
    )?;
    if let Some((organization, child)) = organization {
        model_fields.register_organization_schema(&organization, true, false);
        model_fields.register_model_schema(
            EntityRole::Team,
            Some("linked_team"),
            UserConfig::default(),
        )?;
        model_fields.register_model_schema(
            EntityRole::TeamMember,
            Some("linked_team_member"),
            child,
        )?;
    }
    raw.with_runtime(config, Vec::new(), model_fields)
}

fn date() -> FieldDate {
    FieldDate::from_milliseconds(1_893_456_000_000.0)
}

fn user(id: &str, name: &str, additional_fields: FieldMap) -> CreateUser {
    CreateUser {
        id: Some(id.into()),
        name: Some(name.to_owned()).into(),
        email: Some(format!("{id}@relation-object-mutation.test")),
        email_verified: Some(true),
        image: None::<String>.into(),
        created_at: Some(date()),
        updated_at: Some(date()),
        additional_fields,
        ..Default::default()
    }
}

fn account(id: &str, access_token: &str, user_id: &str) -> CreateAccount {
    CreateAccount {
        id: id.into(),
        account_id: id.into(),
        provider_id: "provider".into(),
        user_id: user_id.into(),
        access_token: Some(access_token.to_owned()).into(),
        refresh_token: Some("refresh".to_owned()).into(),
        id_token: Some("id-token".to_owned()).into(),
        access_token_expires_at: Some(date()).into(),
        refresh_token_expires_at: Some(date()).into(),
        scope: Some("read".to_owned()).into(),
        password: Some("password".to_owned()).into(),
        created_at: date().into(),
        updated_at: date().into(),
        ..Default::default()
    }
}

pub(super) async fn seed_memory(
    store: &dyn AuthStore<StatelessSchema>,
    target: Target,
) -> AuthResult<()> {
    let extra = [(target.physical().into(), COLLISION.into())].into();
    match target {
        Target::User => {
            let _ = store.create_user(user("parent", "Parent", extra)).await?;
            for (id, token) in [("child", "Before"), ("second", "Second")] {
                let _ = store.create_account(account(id, token, "parent")).await?;
            }
        }
        Target::Account => {
            let mut input = account("parent", "Parent", "child");
            input.additional_fields = extra;
            let _ = store.create_account(input).await?;
            let _ = store
                .create_user(user("child", "Before", FieldMap::new()))
                .await?;
        }
        Target::Team => {
            let _ = store
                .create_team(CreateTeam {
                    id: Some("parent".into()),
                    name: "Parent".into(),
                    organization_id: "organization".into(),
                    created_at: Some(date()),
                    additional_fields: extra,
                    ..Default::default()
                })
                .await?;
            for user in ["Before", "Second"] {
                let _ = store
                    .add_team_member(&"parent".into(), user, None)
                    .await?
                    .ok_or_else(|| AuthError::internal("Expected seeded team membership"))?;
            }
        }
    }
    Ok(())
}

pub(super) fn relation(target: Target, rows: &[FieldMap]) -> FieldValue {
    if target.many() {
        rows.iter()
            .cloned()
            .map(FieldValue::from)
            .collect::<Vec<_>>()
            .into()
    } else {
        rows.first()
            .cloned()
            .map_or(FieldValue::Null, FieldValue::from)
    }
}

pub(super) fn first(target: Target, value: &FieldValue) -> AuthResult<FieldValue> {
    if target.many() {
        value
            .as_array()
            .map(|rows| rows.first())
            .transpose()?
            .flatten()
            .ok_or_else(|| AuthError::internal("Expected relation child"))
    } else {
        Ok(value.clone())
    }
}

fn children<T: AuthRecordFields>(rows: JoinValue<T>) -> AuthResult<Vec<FieldMap>> {
    match rows {
        JoinValue::One(row) => row.into_iter().map(|row| row.field_values()).collect(),
        JoinValue::Many(rows) => rows.into_iter().map(|row| row.field_values()).collect(),
    }
}

pub(super) async fn observe<S: AuthSchema>(
    store: &dyn AuthStore<S>,
    target: Target,
) -> TestResult<(FieldMap, Vec<FieldMap>)> {
    match target {
        Target::User => {
            let row = store
                .get_user_with_accounts("parent@relation-object-mutation.test")
                .await?
                .ok_or("Missing User parent")?;
            Ok((row.user.field_values()?, children(row.accounts)?))
        }
        Target::Account => {
            let row = store
                .get_account_owner("provider", "parent")
                .await?
                .ok_or("Missing Account parent")?;
            Ok((row.account.field_values()?, children(row.user)?))
        }
        Target::Team => {
            let row = store
                .get_team_details_value(&"parent".into(), None, true)
                .await?
                .ok_or("Missing Team parent")?;
            Ok((
                row.team.field_values()?,
                children(row.members.ok_or("Missing membership relation")?)?,
            ))
        }
    }
}

async fn insert(database: &DatabaseConnection, table: &str, row: serde_json::Value) -> TestResult {
    let fields = row.as_object().ok_or("Expected seed object")?;
    let columns = fields
        .keys()
        .map(|name| format!("\"{name}\""))
        .collect::<Vec<_>>()
        .join(",");
    let placeholders = vec!["?"; fields.len()].join(",");
    let values = fields
        .values()
        .map(|value| match value {
            serde_json::Value::String(value) => Ok(value.clone().into()),
            serde_json::Value::Number(value) => value
                .as_i64()
                .map(Into::into)
                .ok_or("Expected integer seed"),
            serde_json::Value::Bool(value) => Ok((*value).into()),
            serde_json::Value::Null => Ok(Option::<String>::None.into()),
            _ => Err("Expected scalar seed"),
        })
        .collect::<Result<Vec<better_auth_seaorm::sea_orm::Value>, _>>()?;
    let _ = database
        .execute_raw(Statement::from_sql_and_values(
            DbBackend::Sqlite,
            format!("INSERT INTO \"{table}\" ({columns}) VALUES ({placeholders})"),
            values,
        ))
        .await?;
    Ok(())
}

pub(super) async fn sql_fixture(
    target: Target,
) -> TestResult<(Arc<dyn AuthStore<core_models::Core>>, Storage)> {
    use serde_json::json;
    let database = Database::connect("sqlite::memory:").await?;
    let schema = Schema::new(DbBackend::Sqlite);
    for table in [
        schema.create_table_from_entity(core_models::user::Entity),
        schema.create_table_from_entity(core_models::account::Entity),
        schema.create_table_from_entity(models::team::Entity),
        schema.create_table_from_entity(models::team_member::Entity),
    ] {
        let _ = database
            .execute_raw(DbBackend::Sqlite.build(&table))
            .await?;
    }
    let time = "2030-01-01T00:00:00.000Z";
    let user = |id: &str, name: &str| {
        json!({"id":id,"name":name,"email":format!("{id}@relation-object-mutation.test"),
        "emailVerified":1,"image":null,"createdAt":time,"updatedAt":time})
    };
    let account = |id: &str, token: &str, owner: &str| {
        json!({"id":id,"accountId":id,"providerId":"provider","userId":owner,
        "accessToken":token,"refreshToken":"refresh","idToken":"id-token","accessTokenExpiresAt":time,
        "refreshTokenExpiresAt":time,"scope":"read","password":"password","createdAt":time,"updatedAt":time})
    };
    let mut parent = match target {
        Target::User => user("parent", "Parent"),
        Target::Account => account("parent", "Parent", "child"),
        Target::Team => {
            json!({"id":"parent","name":"Parent","memberCount":2,"organizationId":"organization","createdAt":time,"updatedAt":null})
        }
    };
    let _ = parent
        .as_object_mut()
        .ok_or_else(|| AuthError::internal("Fixture parent must be an object"))?
        .insert(target.physical().into(), json!(COLLISION));
    let parent_table = match target {
        Target::User => "linked_user",
        Target::Account => "linked_account",
        Target::Team => "linked_team",
    };
    insert(&database, parent_table, parent).await?;
    let children = match target {
        Target::User => vec![account("child", "Before", "parent"), account("second", "Second", "parent")],
        Target::Account => vec![user("child", "Before")],
        Target::Team => ["Before", "Second"].into_iter().enumerate().map(|(index, user)| json!({
            "id":if index == 0 { "child" } else { "second" }, "teamId":"parent", "userId":user,
            "membershipKey":format!("membership:{index}"), "createdAt":time,
        })).collect(),
    };
    let selected = children
        .iter()
        .map(|child| {
            Ok(FieldValue::from_json(child.clone())?
                .as_object()
                .ok_or("Expected child seed")?
                .snapshot_fields()?)
        })
        .collect::<TestResult<Vec<FieldMap>>>()?;
    for child in children {
        insert(&database, target.physical(), child).await?;
    }
    let raw = SeaOrmStore::<core_models::Core>::new(AuthConfig::default(), database.clone())
        .with_organization_schema::<models::Organizations>();
    Ok((
        Arc::new(raw),
        Storage::Sqlite {
            database,
            children: selected,
        },
    ))
}
