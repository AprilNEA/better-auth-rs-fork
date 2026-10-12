use super::*;

pub(super) fn request(
    model: &str,
    operation: &str,
    id: &str,
) -> AuthResult<(&'static str, JsonValue)> {
    let selected = json!({"field":"id","value":id});
    let update = json!({"label":"updated","updatedAt":{"type":"date","value":CHANGED_AT}});
    Ok(match operation {
        "findOne" => ("findOne", json!({"model":model,"where":[selected]})),
        "update" => (
            "update",
            json!({"model":model,"where":[selected],"update":update}),
        ),
        "delete" => (
            if model == "verification" {
                "deleteWithHooks"
            } else {
                "delete"
            },
            json!({"model":model,"where":[selected]}),
        ),
        "findMany-in" => (
            "findMany",
            json!({"model":model,"where":[{"field":"id","operator":"in","value":[id]}],"limit":10}),
        ),
        "updateMany-id" => (
            "updateMany",
            json!({"model":model,"where":[selected],"update":update}),
        ),
        "updateMany-provider-id" => (
            "updateMany",
            json!({"model":model,"where":[{"field":"providerId","value":"ordinary-provider"},selected],"update":update}),
        ),
        "list-count-id" | "list-count-_id" | "list-count-search-id" => {
            let conditions = if operation == "list-count-search-id" {
                json!([{"field":"email","operator":"eq","value":"owner@core-query-id.test"},{"field":"id","operator":"eq","value":id}])
            } else {
                json!([{"field":if operation == "list-count-_id" { "_id" } else { "id" },"operator":"eq","value":id}])
            };
            (
                "listUsers+countTotalUsers",
                json!({
                    "findMany":{"model":model,"where":conditions,"limit":10,"offset":0},
                    "count":{"model":model,"where":conditions},
                }),
            )
        }
        _ => return Err(AuthError::internal("Unknown core ID alias request")),
    })
}

fn observe_optional(value: Option<impl AuthRecordFields>) -> AuthResult<JsonValue> {
    value
        .map(|value| observe(value.field_values()?, false))
        .transpose()
        .map(|value| value.unwrap_or(JsonValue::Null))
}

fn observe_rows(values: Vec<impl AuthRecordFields>) -> AuthResult<JsonValue> {
    Ok(json!(
        values
            .into_iter()
            .map(|value| observe(value.field_values()?, false))
            .collect::<AuthResult<Vec<_>>>()?
    ))
}

fn patch() -> AuthResult<FieldMap> {
    Ok([
        ("label".into(), "updated".into()),
        ("updatedAt".into(), date(CHANGED_AT)?.into()),
    ]
    .into())
}

pub(super) async fn execute(
    store: &EphemeralStore,
    model: &str,
    operation: &str,
    id: &str,
) -> AuthResult<JsonValue> {
    let selected = Value::from(id);
    match (model, operation) {
        ("user", "findOne") => observe_optional(store.get_user_by_id_value(&selected).await?),
        ("user", "update") => observe_optional(
            store
                .update_user_by_id_value(
                    &selected,
                    UpdateUser {
                        additional_fields: patch()?,
                        ..Default::default()
                    },
                )
                .await?,
        ),
        ("user", "delete") => {
            store.delete_user_value(&selected).await?;
            Ok(json!({"type":"undefined"}))
        }
        ("user", "findMany-in") => {
            observe_rows(store.list_users_by_id_values(&[selected], 10.0).await?)
        }
        ("user", "list-count-id" | "list-count-_id" | "list-count-search-id") => {
            let search = operation == "list-count-search-id";
            let (users, total) = store
                .list_users(ListUsersParams {
                    limit: Some(10.0),
                    offset: Some(0.0),
                    filter_field: Some(
                        if operation == "list-count-_id" {
                            "_id"
                        } else {
                            "id"
                        }
                        .into(),
                    ),
                    filter_value: Some(selected),
                    filter_operator: Some("eq".into()),
                    search_field: search.then(|| "email".into()),
                    search_value: search.then(|| "owner@core-query-id.test".into()),
                    search_operator: search.then(|| "eq".into()),
                    ..Default::default()
                })
                .await?;
            Ok(json!({"users":observe_rows(users)?,"total":total}))
        }
        ("account", "update") => observe_optional(
            store
                .update_account_by_id_value(
                    &selected,
                    UpdateAccount {
                        additional_fields: patch()?,
                        ..Default::default()
                    },
                )
                .await?,
        ),
        ("account", "updateMany-id" | "updateMany-provider-id") => {
            let mut selectors = FieldMap::new();
            if operation == "updateMany-provider-id" {
                let _ = selectors.insert("providerId".into(), "ordinary-provider".into());
            }
            let _ = selectors.insert("id".into(), selected);
            let result = store
                .update_accounts(
                    &selectors,
                    UpdateAccount {
                        additional_fields: patch()?,
                        ..Default::default()
                    },
                )
                .await?;
            Ok(json!(result))
        }
        ("account", "delete") => {
            store.delete_account_value(&selected).await?;
            Ok(json!({"type":"undefined"}))
        }
        ("verification", "delete") => {
            store.delete_verification(id).await?;
            Ok(json!({"type":"undefined"}))
        }
        _ => Err(AuthError::internal(
            "Unknown core ID alias business operation",
        )),
    }
}
