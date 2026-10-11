use super::*;

pub(super) enum Storage {
    Memory(Box<EphemeralStore>),
    Sqlite(DatabaseConnection),
}
impl Storage {
    pub fn sqlite(&self) -> bool {
        matches!(self, Self::Sqlite(_))
    }
    pub async fn snapshot(&self) -> AuthResult<BTreeMap<String, Vec<FieldMap>>> {
        let mut snapshot = BTreeMap::new();
        for (model, table, role) in [
            ("user", "users", EntityRole::User),
            ("session", "sessions", EntityRole::Session),
            ("account", "accounts", EntityRole::Account),
            ("verification", "verifications", EntityRole::Verification),
            ("organization", "organization", EntityRole::Organization),
            ("member", "member", EntityRole::Member),
            ("invitation", "invitation", EntityRole::Invitation),
            ("team", "team", EntityRole::Team),
            ("teamMember", "team_member", EntityRole::TeamMember),
        ] {
            let mut rows = match self {
                Self::Memory(store) => store.storage_rows(role)?,
                Self::Sqlite(database) => {
                    let columns = database
                        .query_all_raw(Statement::from_string(
                            DbBackend::Sqlite,
                            format!("PRAGMA table_info(\"{table}\")"),
                        ))
                        .await
                        .map_err(db_error)?;
                    let columns = columns
                        .iter()
                        .map(|row| row.try_get::<String>("", "name").map_err(db_error))
                        .collect::<AuthResult<Vec<_>>>()?;
                    let fields = columns
                        .iter()
                        .map(|name| {
                            format!(
                                "'{}', \"{}\"",
                                name.replace('\'', "''"),
                                name.replace('"', "\"\"")
                            )
                        })
                        .collect::<Vec<_>>()
                        .join(", ");
                    database.query_all_raw(Statement::from_string(DbBackend::Sqlite, format!("SELECT json_object({fields}) AS record FROM \"{table}\" ORDER BY id"))).await.map_err(db_error)?.into_iter().map(|row| {
                        FieldMap::from_json(serde_json::from_str(&row.try_get::<String>("", "record").map_err(db_error)?)?)
                    }).collect::<AuthResult<Vec<_>>>()?
                }
            };
            rows.sort_by(|left, right| {
                left.get("id")
                    .and_then(FieldValue::as_str)
                    .cmp(&right.get("id").and_then(FieldValue::as_str))
            });
            let _ = snapshot.insert(model.into(), rows);
        }
        Ok(snapshot)
    }
}
fn db_error(error: better_auth_seaorm::sea_orm::DbErr) -> AuthError {
    AuthError::internal(error.to_string())
}

pub(super) async fn seed<S: AuthSchema>(
    store: &dyn AuthStore<S>,
    parent: Parent,
    case: Case,
) -> AuthResult<String> {
    let _ = store
        .create_user(CreateUser {
            id: Some("user".into()),
            created_at: Some(date()),
            updated_at: Some(date()),
            image: None.into(),
            ..CreateUser::new()
                .with_name("Owner")
                .with_email("owner@list-relations.test")
                .with_email_verified(true)
        })
        .await?;
    for suffix in ["a", "b", "c"] {
        let _ = store
            .insert_organization(Organization {
                field_order: Default::default(),
                id: format!("org-{suffix}").into(),
                name: format!("Organization {suffix}").into(),
                slug: format!("slug-{suffix}").into(),
                logo: Some(if suffix == "c" { "other" } else { "linked" }.to_owned()).into(),
                metadata: None::<FieldValue>.into(),
                created_at: date().into(),
                additional_fields: FieldMap::new(),
            })
            .await?;
    }
    for (index, role) in case.parent_roles().into_iter().enumerate() {
        if parent == Parent::Member {
            let _ = store
                .insert_member(Member {
                    id: format!("parent-{index}").into(),
                    organization_id: "org-a".into(),
                    user_id: "user".into(),
                    role: role.into(),
                    created_at: date().into(),
                    additional_fields: FieldMap::new(),
                    field_order: Default::default(),
                })
                .await?;
        } else {
            let _ = store
                .create_invitation(CreateInvitation {
                    id: Some(format!("parent-{index}")),
                    created_at: Some(date()),
                    ..CreateInvitation::new(
                        "org-a",
                        "owner@list-relations.test",
                        role,
                        "user",
                        date(),
                    )
                })
                .await?;
        }
    }
    let session = store
        .create_session(CreateSession {
            user_id: "user".into(),
            expires_at: date(),
            active_organization_id: None,
            ip_address: None,
            user_agent: None,
            impersonated_by: None,
            inherited_fields: Default::default(),
            additional_fields: [("activeTeamId".into(), FieldValue::Null)].into(),
        })
        .await?;
    Ok(session.token.typed()?.clone())
}
