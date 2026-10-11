use super::*;
use better_auth_core::Member;
use better_auth_seaorm::sea_orm::{ConnectionTrait, DatabaseConnection, DbBackend, Statement};

pub(super) fn date() -> FieldDate {
    FieldDate::from_milliseconds(1_893_456_000_000.0)
}

#[derive(Clone)]
pub(super) enum Storage {
    Memory(Box<EphemeralStore>),
    Sqlite(DatabaseConnection),
}

impl Storage {
    pub(super) fn memory(&self) -> bool {
        matches!(self, Self::Memory(_))
    }

    pub(super) async fn snapshot(
        &self,
    ) -> AuthResult<std::collections::BTreeMap<String, Vec<FieldMap>>> {
        self.snapshot_with_roles(false).await
    }

    pub(super) async fn snapshot_with_roles(
        &self,
        roles: bool,
    ) -> AuthResult<std::collections::BTreeMap<String, Vec<FieldMap>>> {
        let mut snapshot = std::collections::BTreeMap::new();
        let mut tables = vec![
            ("user", "users", EntityRole::User),
            ("session", "sessions", EntityRole::Session),
            ("account", "accounts", EntityRole::Account),
            ("verification", "verifications", EntityRole::Verification),
            ("organization", "organization", EntityRole::Organization),
            ("member", "member", EntityRole::Member),
            ("invitation", "invitation", EntityRole::Invitation),
            ("team", "team", EntityRole::Team),
            ("teamMember", "team_member", EntityRole::TeamMember),
        ];
        if roles {
            tables.push((
                "organizationRole",
                "organization_role",
                EntityRole::OrganizationRole,
            ));
        }
        for (name, table, role) in tables {
            let mut rows = match self {
                Self::Memory(store) => store.storage_rows(role)?,
                Self::Sqlite(database) => {
                    let columns = database
                        .query_all_raw(Statement::from_string(
                            DbBackend::Sqlite,
                            format!("PRAGMA table_info(\"{table}\")"),
                        ))
                        .await
                        .map_err(|error| AuthError::internal(error.to_string()))?;
                    let columns = columns
                        .iter()
                        .map(|row| row.try_get::<String>("", "name"))
                        .collect::<Result<Vec<_>, _>>()
                        .map_err(|error| AuthError::internal(error.to_string()))?;
                    let columns = columns
                        .iter()
                        .map(|name| format!("'{name}',\"{name}\""))
                        .collect::<Vec<_>>()
                        .join(",");
                    database.query_all_raw(Statement::from_string(DbBackend::Sqlite,
                        format!("SELECT json_object({columns}) AS value FROM \"{table}\" ORDER BY id"),
                    )).await.map_err(|error| AuthError::internal(error.to_string()))?
                        .into_iter().map(|row| {
                            let json = row.try_get::<String>("", "value")
                                .map_err(|error| AuthError::internal(error.to_string()))?;
                            FieldMap::from_json(serde_json::from_str(&json)?)
                        }).collect::<AuthResult<Vec<_>>>()?
                }
            };
            rows.sort_by(|left, right| {
                left.get("id")
                    .and_then(FieldValue::as_str)
                    .cmp(&right.get("id").and_then(FieldValue::as_str))
            });
            let _ = snapshot.insert(name.into(), rows);
        }
        Ok(snapshot)
    }
}

pub(super) fn memory_fixture() -> (Arc<dyn AuthStore<StatelessSchema>>, Storage) {
    let store = EphemeralStore::new(Arc::new(config()));
    (Arc::new(store.clone()), Storage::Memory(Box::new(store)))
}

pub(super) async fn sqlite_fixture() -> AuthResult<(Arc<dyn AuthStore<BundledSchema>>, Storage)> {
    let database = Database::connect("sqlite::memory:")
        .await
        .map_err(|error| AuthError::internal(error.to_string()))?;
    migrator::run_migrations(&database)
        .await
        .map_err(|error| AuthError::internal(error.to_string()))?;
    Ok((
        Arc::new(SeaOrmStore::<BundledSchema>::new(
            config(),
            database.clone(),
        )),
        Storage::Sqlite(database),
    ))
}

pub(super) fn member(id: &str, user: &str, role: &str) -> Member {
    Member {
        field_order: Default::default(),
        additional_fields: Default::default(),
        id: id.into(),
        organization_id: "organization".into(),
        user_id: user.into(),
        role: role.into(),
        created_at: date().into(),
    }
}

pub(super) async fn seed<S: AuthSchema>(
    raw: Arc<dyn AuthStore<S>>,
    target: bool,
    actor: &str,
) -> AuthResult<String> {
    for id in ["user-a", "user-b"] {
        let _ = raw
            .create_user(CreateUser {
                id: Some(id.into()),
                created_at: Some(date()),
                updated_at: Some(date()),
                image: None.into(),
                ..CreateUser::new()
                    .with_name(id)
                    .with_email(format!("{id}@fields.test"))
                    .with_email_verified(true)
            })
            .await?;
    }
    let _ = raw
        .insert_organization(Organization {
            field_order: Default::default(),
            id: "organization".into(),
            name: "Organization".into(),
            slug: "organization".into(),
            logo: None.into(),
            metadata: Some(FieldValue::from("{}")).into(),
            created_at: date().into(),
            additional_fields: Default::default(),
        })
        .await?;
    let _ = raw
        .insert_member(member("owner-member", "user-a", "owner"))
        .await?;
    if target {
        let _ = raw
            .insert_member(member("member-b", "user-b", "member"))
            .await?;
    }
    let auth = BetterAuth::new(config())
        .store_arc(raw)
        .plugin(OrganizationPlugin::with_config(
            OrganizationConfig::default(),
        ))
        .build()
        .await?;
    let session = auth
        .store()
        .create_session(CreateSession {
            user_id: actor.into(),
            expires_at: FieldDate::from_milliseconds(4_102_444_800_000.0),
            active_organization_id: Some("organization".into()),
            inherited_fields: Default::default(),
            additional_fields: Default::default(),
            ip_address: None,
            user_agent: None,
            impersonated_by: None,
        })
        .await?;
    Ok(session.token.typed()?.clone())
}

#[expect(
    clippy::panic_in_result_fn,
    reason = "Contract assertions report mismatches while setup and callback errors propagate"
)]
pub(super) fn ordered(actual: &FieldValue, expected: &FieldValue) -> AuthResult<()> {
    assert_eq!(actual, expected);
    if let (Some(actual), Some(expected)) = (actual.as_object(), expected.as_object()) {
        let actual = actual.snapshot_fields()?;
        let expected = expected.snapshot_fields()?;
        assert_eq!(
            actual.keys().collect::<Vec<_>>(),
            expected.keys().collect::<Vec<_>>()
        );
        for (name, value) in &expected {
            ordered(required(actual.get(name), "Expected ordered field")?, value)?;
        }
    } else if let (Some(actual), Some(expected)) = (actual.as_array(), expected.as_array()) {
        for (actual, expected) in actual.iter().zip(expected) {
            ordered(actual, expected)?;
        }
    }
    Ok(())
}
