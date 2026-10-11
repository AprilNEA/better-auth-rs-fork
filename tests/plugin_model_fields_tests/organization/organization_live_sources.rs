use super::*;
use std::sync::atomic::{AtomicUsize, Ordering};
use tokio::sync::Notify;

#[path = "organization_live_sources_support.rs"]
mod support;
use support::{
    Events, Ids, Model, Storage, auth, auth_config, check_storage, create, date, declaration,
    delete, event, list, memory_fixture, mutate, ordered, past, point, replace, seed_parents,
    sqlite_fixture, stored, update, updated, visible,
};

#[path = "organization_live_consumption.rs"]
mod consumption;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Operation {
    Create,
    Update,
    Point,
    List,
}

fn output_policy(model: Model, transform: UserFieldTransform) -> UserFieldConfig {
    UserFieldConfig {
        field_type: if model == Model::Invitation {
            UserFieldType::Date
        } else {
            UserFieldType::String
        },
        transform: Some(FieldTransforms {
            output: Some(transform),
            ..Default::default()
        }),
        ..Default::default()
    }
}

fn raw_late(storage: &Storage, value: FieldValue) -> AuthResult<FieldValue> {
    if !storage.memory() && value.as_date().is_some() {
        FieldValue::from_json(required(value.json()?, "Expected Date JSON")?)
    } else {
        Ok(value)
    }
}

async fn live<S: AuthSchema>(
    raw: Arc<dyn AuthStore<S>>,
    storage: Storage,
    model: Model,
    operation: Operation,
) -> AuthResult<()> {
    let _ = seed_parents(raw.clone()).await?;
    let ids = Ids::default();
    let writer = auth(raw.clone(), ids.clone(), Vec::new()).await?;
    if operation != Operation::Create {
        let _ = create(writer.store().as_ref(), &ids, model, "source-a", "First").await?;
    }
    let mut expected_storage = storage.snapshot_with_roles(true).await?;
    let events = Events::default();
    let fields = declaration([
        (
            model.early(),
            UserFieldConfig {
                transform: Some(FieldTransforms {
                    output: Some(UserFieldTransform::new_async({
                        let events = events.clone();
                        let writer = writer.store().clone();
                        move |value| {
                            let events = events.clone();
                            let writer = writer.clone();
                            async move {
                                event(&events, "early", value.clone())?;
                                mutate(writer.as_ref(), model, "source-a").await?;
                                Ok(value)
                            }
                        }
                    })),
                    ..Default::default()
                }),
                ..Default::default()
            },
        ),
        (
            model.late(),
            output_policy(
                model,
                UserFieldTransform::new({
                    let events = events.clone();
                    move |value| {
                        event(&events, "late", value.clone())?;
                        Ok(value)
                    }
                }),
            ),
        ),
    ]);
    let reader = auth(raw, ids.clone(), vec![(model.role(), fields)]).await?;
    let started = chrono::Utc::now().timestamp_millis();
    let actual = match operation {
        Operation::Create => {
            vec![create(reader.store().as_ref(), &ids, model, "source-a", "First").await?]
        }
        Operation::Update => vec![update(reader.store().as_ref(), model, "source-a").await?],
        Operation::Point => vec![point(reader.store().as_ref(), model, "source-a").await?],
        Operation::List => list(reader.store().as_ref(), model).await?,
    };
    let mut expected = visible(model, "source-a", "First");
    if operation == Operation::Update {
        expected = updated(model, expected);
    }
    let early = required(expected.get(model.early()), "Expected early field")?.clone();
    let initial = required(expected.get(model.late()), "Expected later field")?.clone();
    let projected = if storage.memory() {
        model.changed()
    } else {
        initial
    };
    let _ = expected.insert(model.late().into(), projected.clone());
    ordered(
        &actual
            .into_iter()
            .map(FieldValue::from)
            .collect::<Vec<_>>()
            .into(),
        &vec![FieldValue::from(expected.clone())].into(),
    )?;
    ordered(
        &trace_lock(&events)?.clone().into(),
        &vec![
            FieldValue::from(vec!["early".into(), early]),
            FieldValue::from(vec!["late".into(), raw_late(&storage, projected)?]),
        ]
        .into(),
    )?;
    let _ = expected.insert(model.late().into(), model.changed());
    replace(
        &mut expected_storage,
        model,
        "source-a",
        stored(&storage, &expected)?,
    )?;
    check_storage(
        &storage,
        &mut expected_storage,
        model,
        &["source-a"],
        started,
    )
    .await
}

async fn selected<S: AuthSchema>(
    raw: Arc<dyn AuthStore<S>>,
    storage: Storage,
    model: Model,
) -> AuthResult<()> {
    let _ = seed_parents(raw.clone()).await?;
    let ids = Ids::default();
    let writer = auth(raw.clone(), ids.clone(), Vec::new()).await?;
    for (id, label) in [("source-a", "First"), ("source-b", "Second")] {
        let _ = create(writer.store().as_ref(), &ids, model, id, label).await?;
    }
    let mut expected_storage = storage.snapshot_with_roles(true).await?;
    let events = Events::default();
    let gate = Arc::new(Notify::new());
    let calls = Arc::new(AtomicUsize::new(0));
    let fields = declaration([
        (
            model.early(),
            UserFieldConfig {
                transform: Some(FieldTransforms {
                    output: Some(UserFieldTransform::new_async({
                        let events = events.clone();
                        let gate = gate.clone();
                        let writer = writer.store().clone();
                        let ids = ids.clone();
                        move |value| {
                            let events = events.clone();
                            let gate = gate.clone();
                            let writer = writer.clone();
                            let ids = ids.clone();
                            let first = calls.fetch_add(1, Ordering::SeqCst) == 0;
                            async move {
                                event(&events, "early", value.clone())?;
                                if first {
                                    gate.notified().await;
                                    mutate(writer.as_ref(), model, "source-a").await?;
                                    delete(writer.as_ref(), model, "source-a").await?;
                                    let _ = create(
                                        writer.as_ref(),
                                        &ids,
                                        model,
                                        "source-a",
                                        "Replacement",
                                    )
                                    .await?;
                                    let _ =
                                        create(writer.as_ref(), &ids, model, "source-c", "Third")
                                            .await?;
                                }
                                Ok(value)
                            }
                        }
                    })),
                    ..Default::default()
                }),
                ..Default::default()
            },
        ),
        (
            model.late(),
            output_policy(
                model,
                UserFieldTransform::new({
                    let events = events.clone();
                    let gate = gate.clone();
                    move |value| {
                        event(&events, "late", value.clone())?;
                        gate.notify_one();
                        Ok(value)
                    }
                }),
            ),
        ),
    ]);
    let reader = auth(raw, ids, vec![(model.role(), fields)]).await?;
    let started = chrono::Utc::now().timestamp_millis();
    let actual = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        list(reader.store().as_ref(), model),
    )
    .await
    .map_err(|_| {
        AuthError::internal("Selected-object projection did not release the callback gate")
    })??;
    let mut first = visible(model, "source-a", "First");
    let second = visible(model, "source-b", "Second");
    let initial = required(first.get(model.late()), "Expected later field")?.clone();
    let projected = if storage.memory() {
        model.changed()
    } else {
        initial.clone()
    };
    let _ = first.insert(model.late().into(), projected.clone());
    ordered(
        &actual
            .into_iter()
            .map(FieldValue::from)
            .collect::<Vec<_>>()
            .into(),
        &vec![
            FieldValue::from(first.clone()),
            FieldValue::from(second.clone()),
        ]
        .into(),
    )?;
    ordered(
        &trace_lock(&events)?.clone().into(),
        &vec![
            FieldValue::from(vec![
                "early".into(),
                required(first.get(model.early()), "Expected first early field")?.clone(),
            ]),
            FieldValue::from(vec![
                "early".into(),
                required(second.get(model.early()), "Expected second early field")?.clone(),
            ]),
            FieldValue::from(vec!["late".into(), raw_late(&storage, initial)?]),
            FieldValue::from(vec!["late".into(), raw_late(&storage, projected)?]),
        ]
        .into(),
    )?;
    for (id, label) in [("source-a", "Replacement"), ("source-c", "Third")] {
        replace(
            &mut expected_storage,
            model,
            id,
            stored(&storage, &visible(model, id, label))?,
        )?;
    }
    check_storage(
        &storage,
        &mut expected_storage,
        model,
        &["source-a", "source-c"],
        started,
    )
    .await
}

async fn duplicates<S: AuthSchema>(
    raw: Arc<dyn AuthStore<S>>,
    storage: Storage,
    model: Model,
) -> AuthResult<()> {
    let _ = seed_parents(raw.clone()).await?;
    let ids = Ids::default();
    let writer = auth(raw.clone(), ids.clone(), Vec::new()).await?;
    let _ = create(writer.store().as_ref(), &ids, model, "source-a", "First").await?;
    let before = storage.snapshot_with_roles(true).await?;
    let events = Events::default();
    let policies = declaration([(
        model.early(),
        UserFieldConfig {
            transform: Some(FieldTransforms {
                output: Some(UserFieldTransform::new({
                    let events = events.clone();
                    move |value| {
                        event(&events, "early", value.clone())?;
                        Ok(value)
                    }
                })),
                ..Default::default()
            }),
            ..Default::default()
        },
    )]);
    let reader = auth(raw, ids.clone(), vec![(model.role(), policies)]).await?;
    if !storage.memory() {
        let error = create(reader.store().as_ref(), &ids, model, "source-a", "Second")
            .await
            .expect_err("SQLite must reject duplicate primary IDs");
        assert!(
            error.to_string().contains("UNIQUE constraint failed"),
            "{error}"
        );
        assert!(trace_lock(&events)?.is_empty());
        assert_eq!(storage.snapshot_with_roles(true).await?, before);
        return Ok(());
    }
    let _ = create(writer.store().as_ref(), &ids, model, "source-a", "Second").await?;
    let mut after = storage.snapshot_with_roles(true).await?;
    let actual = update(reader.store().as_ref(), model, "source-a").await?;
    let first = updated(model, visible(model, "source-a", "First"));
    let second = updated(model, visible(model, "source-a", "Second"));
    ordered(&actual.into(), &first.clone().into())?;
    ordered(
        &trace_lock(&events)?.clone().into(),
        &vec![FieldValue::from(vec![
            "early".into(),
            required(first.get(model.early()), "Expected early field")?.clone(),
        ])]
        .into(),
    )?;
    let rows = after
        .get_mut(model.table())
        .ok_or_else(|| AuthError::internal("Expected model storage"))?;
    rows.retain(|row| row.get("id").and_then(FieldValue::as_str) != Some("source-a"));
    rows.extend([stored(&storage, &first)?, stored(&storage, &second)?]);
    rows.sort_by(|left, right| {
        left.get("id")
            .and_then(FieldValue::as_str)
            .cmp(&right.get("id").and_then(FieldValue::as_str))
    });
    assert_eq!(storage.snapshot_with_roles(true).await?, after);
    Ok(())
}

#[tokio::test]
async fn ordinary_model_crud_preserves_live_rows_and_sql_snapshots() -> AuthResult<()> {
    for model in Model::ALL {
        for operation in [
            Operation::Create,
            Operation::Update,
            Operation::Point,
            Operation::List,
        ] {
            let (raw, storage) = memory_fixture();
            live(raw, storage, model, operation).await?;
            let (raw, storage) = sqlite_fixture().await?;
            live(raw, storage, model, operation).await?;
        }
    }
    Ok(())
}

#[tokio::test]
async fn ordinary_model_lists_keep_selected_objects_after_delete_and_recreate() -> AuthResult<()> {
    for model in [Model::Organization, Model::Team, Model::Role] {
        let (raw, storage) = memory_fixture();
        selected(raw, storage, model).await?;
        let (raw, storage) = sqlite_fixture().await?;
        selected(raw, storage, model).await?;
    }
    Ok(())
}

#[tokio::test]
async fn ordinary_model_duplicate_ids_preserve_backend_write_rules() -> AuthResult<()> {
    for model in Model::ALL {
        let (raw, storage) = memory_fixture();
        duplicates(raw, storage, model).await?;
        let (raw, storage) = sqlite_fixture().await?;
        duplicates(raw, storage, model).await?;
    }
    Ok(())
}
