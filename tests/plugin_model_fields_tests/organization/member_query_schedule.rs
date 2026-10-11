use super::member_contract_support::{
    Storage, date, memory_fixture, ordered, seed, sqlite_fixture,
};
use super::*;
use better_auth::server_api::EndpointInput;
use better_auth_core::{HttpMethod, Member};
use std::collections::HashMap;

type Events = Arc<Mutex<Vec<FieldValue>>>;

#[derive(Clone, Copy, Debug)]
enum Case {
    Insertion,
    Page,
    Chronological,
    InvalidSort(usize),
    ScalarIn(&'static str),
}

impl Case {
    const ALL: [Self; 8] = [
        Self::Insertion,
        Self::Page,
        Self::Chronological,
        Self::InvalidSort(0),
        Self::InvalidSort(1),
        Self::InvalidSort(3),
        Self::ScalarIn("role"),
        Self::ScalarIn("unknown"),
    ];
    fn size(self) -> usize {
        if let Self::InvalidSort(size) = self {
            size
        } else {
            3
        }
    }
    #[expect(
        clippy::unreachable,
        reason = "Error cases must return before constructing successful result rows"
    )]
    fn ids(self) -> &'static [&'static str] {
        match self {
            Self::Insertion => &["member-z", "member-a", "member-m"],
            Self::Page => &["member-a"],
            Self::Chronological => &["member-a", "member-m", "member-z"],
            Self::InvalidSort(0) => &[],
            Self::InvalidSort(1) => &["member-a"],
            Self::InvalidSort(_) | Self::ScalarIn(_) => unreachable!(),
        }
    }
}

#[expect(
    clippy::unreachable,
    reason = "Fixture rows use only the three declared member IDs"
)]
fn values(id: &str, visible: bool) -> FieldMap {
    let (user, seconds) = match id {
        "member-z" => ("user-z", 30),
        "member-a" => ("user-a-query", 10),
        "member-m" => ("user-m", 20),
        _ => unreachable!(),
    };
    FieldMap::from_iter([
        ("organizationId".into(), "organization".into()),
        ("userId".into(), user.into()),
        (
            "role".into(),
            if visible {
                "selected:visible"
            } else {
                "selected"
            }
            .into(),
        ),
        (
            "createdAt".into(),
            FieldDate::from_milliseconds(1_893_456_000_000.0 + f64::from(seconds) * 1_000.0).into(),
        ),
        ("id".into(), id.into()),
    ])
}

fn visible_member(id: &str) -> AuthResult<FieldValue> {
    let mut fields = values(id, true);
    let user = required(
        fields.get("userId").and_then(FieldValue::as_str),
        "Expected seeded user ID",
    )?;
    let user = FieldMap::from_iter([
        ("id".into(), user.into()),
        ("name".into(), user.into()),
        (
            "email".into(),
            format!("{user}@team-member-fields.test").into(),
        ),
        ("image".into(), FieldValue::Null),
    ]);
    let _ = fields.insert("user".into(), user.into());
    Ok(fields.into())
}

async fn check<S: AuthSchema>(
    raw: Arc<dyn AuthStore<S>>,
    storage: Storage,
    case: Case,
) -> AuthResult<()> {
    let token = seed(raw.clone(), false, "user-a").await?;
    for id in ["member-z", "member-a", "member-m"] {
        let fields = values(id, false);
        let user = required(
            fields.get("userId").and_then(FieldValue::as_str),
            "Expected seeded user ID",
        )?;
        let _ = raw
            .create_user(CreateUser {
                id: Some(user.into()),
                created_at: Some(date()),
                updated_at: Some(date()),
                image: None.into(),
                ..CreateUser::new()
                    .with_name(user)
                    .with_email(format!("{user}@team-member-fields.test"))
                    .with_email_verified(true)
            })
            .await?;
        let _ = raw
            .insert_member(<Member as better_auth_core::FromFieldMap>::from_field_values(fields)?)
            .await?;
    }
    let before = storage.snapshot().await?;
    assert_eq!(before.len(), 9);
    let events = Events::default();
    let output = events.clone();
    let mut fields = UserConfig::default();
    let _ = fields.fields_mut().insert(
        "role".into(),
        UserFieldConfig {
            transform: Some(FieldTransforms {
                input: Some(UserFieldTransform::new(|_| {
                    Err(AuthError::internal("query-input-must-not-run"))
                })),
                output: Some(UserFieldTransform::new(move |value| {
                    let role = required(value.as_str(), "Expected stored Member role")?.to_owned();
                    trace_lock(&output)?.push(vec!["role".into(), "output".into(), value].into());
                    Ok(format!("{role}:visible").into())
                })),
            }),
            ..Default::default()
        },
    );
    let auth = BetterAuth::new(config())
        .store_arc(raw)
        .plugin(OrganizationPlugin::with_config(
            OrganizationConfig::default(),
        ))
        .plugin(Fields(vec![(EntityRole::Member, fields)]))
        .build()
        .await?;
    let signed = better_auth_core::utils::cookie_utils::sign_cookie_value(
        &token,
        auth.config().signing_secret(),
    );
    let headers = HashMap::from([
        ("content-type".into(), "application/json".into()),
        ("origin".into(), "http://fields.test".into()),
        (
            "cookie".into(),
            format!("better-auth.session_token={signed}"),
        ),
    ]);
    let mut query = serde_json::Map::from_iter([
        ("organizationId".into(), json!("organization")),
        ("filterField".into(), json!("role")),
        ("filterValue".into(), json!("selected")),
    ]);
    match case {
        Case::Insertion => {}
        Case::Page => {
            let _ = query.insert("limit".into(), json!(1));
            let _ = query.insert("offset".into(), json!(1));
        }
        Case::Chronological => {
            let _ = query.insert("sortBy".into(), json!("createdAt"));
            let _ = query.insert("sortDirection".into(), json!("asc"));
        }
        Case::InvalidSort(size) => {
            let _ = query.insert("sortBy".into(), json!("unknown"));
            if size < 2 {
                let _ = query.insert("filterField".into(), json!("userId"));
                let _ = query.insert(
                    "filterValue".into(),
                    json!(if size == 0 { "absent" } else { "user-a-query" }),
                );
            }
        }
        Case::ScalarIn(field) => {
            let _ = query.insert("filterField".into(), json!(field));
            let _ = query.insert("filterOperator".into(), json!("in"));
        }
    }
    let result = auth
        .call_endpoint(
            HttpMethod::Get,
            "/organization/list-members",
            EndpointInput {
                headers: Some(headers),
                query: Some(Value::Object(query)),
                ..Default::default()
            },
        )
        .await;
    let mut expected_events = vec![FieldValue::from(vec![
        "role".into(),
        "output".into(),
        "owner".into(),
    ])];
    if matches!(case, Case::ScalarIn(_)) {
        assert!(
            matches!(required(result.err(), "Scalar in values must fail before resolving the filter field")?,
            AuthError::Config(message) if message == "Value must be an array")
        );
    } else if matches!(case, Case::InvalidSort(size) if !storage.memory() || size >= 2) {
        assert!(
            matches!(required(result.err(), "Invalid sort must fail at the backend's resolution boundary")?,
            AuthError::Config(message) if message == "Field unknown not found in model member")
        );
    } else {
        let response = result?;
        assert_eq!(response.status, 200, "{case:?}");
        let expected = FieldValue::from(FieldMap::from_iter([
            (
                "members".into(),
                case.ids()
                    .iter()
                    .map(|id| visible_member(id))
                    .collect::<AuthResult<Vec<_>>>()?
                    .into(),
            ),
            ("total".into(), case.size().into()),
        ]));
        ordered(&response.body.field_value()?, &expected)?;
        assert_eq!(
            response.body.bytes()?,
            serde_json::to_vec(&expected.json()?)?,
            "{case:?} complete JSON"
        );
        expected_events.extend(vec![
            FieldValue::from(vec![
                "role".into(),
                "output".into(),
                "selected".into()
            ]);
            case.ids().len()
        ]);
    }
    assert_eq!(*trace_lock(&events)?, expected_events, "{case:?}");
    assert_eq!(storage.snapshot().await?, before, "{case:?}");
    Ok(())
}

#[tokio::test]
async fn memory_member_queries_preserve_insertion_pages_counts_and_lazy_sort_validation()
-> AuthResult<()> {
    for case in Case::ALL {
        let (raw, storage) = memory_fixture();
        check(raw, storage, case).await?;
    }
    Ok(())
}

#[tokio::test]
async fn sqlite_member_queries_preserve_pages_counts_and_eager_sort_validation() -> AuthResult<()> {
    for case in Case::ALL {
        let (raw, storage) = sqlite_fixture().await?;
        check(raw, storage, case).await?;
    }
    Ok(())
}
