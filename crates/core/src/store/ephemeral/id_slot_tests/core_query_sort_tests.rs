use super::core_query_alias_tests::{
    configured_reader, configured_writer, core_memory, revive_fields,
};
use super::*;

const OPERATIONS: [&str; 3] = ["sort-only", "sort-after-email", "sort-after-id-in"];

fn property<'a>(value: &'a JsonValue, name: &str) -> AuthResult<&'a JsonValue> {
    required(value.get(name))
}

fn sort_writer(serial: bool) -> AuthResult<EphemeralStore> {
    let writer = configured_writer("user", serial)?;
    let mut config = (*writer.config).clone();
    *config.user.fields_mut() = [
        (
            "selectionId".into(),
            UserFieldConfig {
                field_name: Some("old_id".into()),
                field_type: if serial {
                    crate::user_fields::UserFieldType::Number
                } else {
                    crate::user_fields::UserFieldType::String
                },
                ..Default::default()
            },
        ),
        ("label".into(), UserFieldConfig::default()),
    ]
    .into();
    Ok(EphemeralStore::new(Arc::new(config)))
}

fn request(operation: &str) -> AuthResult<(JsonValue, ListUsersParams)> {
    let mut params = ListUsersParams {
        limit: Some(10.0),
        offset: Some(0.0),
        sort_by: Some("id".into()),
        sort_direction: Some("asc".into()),
        ..Default::default()
    };
    let conditions = match operation {
        "sort-only" => json!([]),
        "sort-after-email" => {
            params.filter_field = Some("email".into());
            params.filter_value = Some("@core-query-id-sort.test".into());
            params.filter_operator = Some("contains".into());
            json!([{"field":"email","operator":"contains","value":"@core-query-id-sort.test"}])
        }
        "sort-after-id-in" => {
            params.filter_field = Some("id".into());
            params.filter_value = Some(vec![Value::from("1"), Value::from("2")].into());
            params.filter_operator = Some("in".into());
            json!([{"field":"id","operator":"in","value":["1","2"]}])
        }
        _ => return Err(AuthError::internal("Unknown core ID sorting operation")),
    };
    Ok((
        json!({
            "findMany":{"model":"user","where":conditions,"sortBy":{"field":"id","direction":"asc"},"limit":10,"offset":0},
            "count":{"model":"user","where":conditions},
        }),
        params,
    ))
}

async fn seed(writer: &EphemeralStore, expected: &JsonValue) -> AuthResult<()> {
    let data = revive_fields(property(property(expected, "input")?, "data")?)?;
    let input = json!({"model":"user","forceAllowId":true,"data":observe(data.clone(), false)?});
    let before = core_memory(writer)?;
    let result = required(writer.create_user_fields_optional(data).await?)?.field_values()?;
    let after = core_memory(writer)?;
    assert_eq!(
        json!({"input":input,"before":before,"result":observe(result, false)?,"after":after}),
        *expected
    );
    Ok(())
}

async fn verify_case(expected: &JsonValue) -> AuthResult<()> {
    let operation = required(property(expected, "operation")?.as_str())?;
    let serial = required(property(expected, "serial")?.as_bool())?;
    assert_eq!(property(expected, "model")?, "user");
    assert_eq!(property(expected, "idFieldName")?, "old_id");
    let writer = sort_writer(serial)?;
    let setup = required(property(expected, "setup")?.as_array())?;
    assert_eq!(setup.len(), 2);
    for expected in setup {
        seed(&writer, expected).await?;
    }
    let trace = Events::default();
    let reader = configured_reader(&writer, "user", &trace)?;
    let steps = required(property(expected, "steps")?.as_array())?;
    assert_eq!(steps.len(), 2);
    for (index, expected) in steps.iter().enumerate() {
        let (input, params) = request(operation)?;
        let before = core_memory(&writer)?;
        let (users, total) = reader.list_users(params).await?;
        let users = users
            .into_iter()
            .map(|user| observe(user.field_values()?, false))
            .collect::<AuthResult<Vec<_>>>()?;
        let after = core_memory(&writer)?;
        let events = std::mem::take(
            &mut *trace
                .lock()
                .map_err(|_| AuthError::internal("Core ID sorting event lock poisoned"))?,
        );
        assert_eq!(users.len(), 2);
        assert_eq!(total, 2);
        assert_eq!(
            json!({
                "attempt":index + 1,"method":"listUsers+countTotalUsers","input":input,
                "before":before,"result":{"users":users,"total":total},"events":events,"after":after,
            }),
            *expected,
            "{operation}, serial={serial}, attempt={}",
            index + 1,
        );
    }
    Ok(())
}

#[tokio::test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "The fixture must contain all six operation and ID-generation combinations."
)]
async fn user_sorting_observes_id_state_after_where_and_before_output() -> AuthResult<()> {
    let fixture: JsonValue = serde_json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../tests/fixtures/core-query-id-sort-1.7.6.json"
    )))?;
    assert_eq!(property(&fixture, "version")?, "1.7.6");
    assert_eq!(property(&fixture, "backend")?, "memory");
    let cases = required(property(&fixture, "cases")?.as_array())?;
    let identities = cases
        .iter()
        .map(|case| {
            Ok(json!([
                property(case, "operation")?,
                property(case, "serial")?,
            ]))
        })
        .collect::<AuthResult<Vec<_>>>()?;
    let expected = OPERATIONS
        .into_iter()
        .flat_map(|operation| [false, true].map(|serial| json!([operation, serial])))
        .collect::<Vec<_>>();
    assert_eq!(identities, expected);
    for case in cases {
        verify_case(case).await?;
    }
    Ok(())
}
