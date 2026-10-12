use super::*;

#[tokio::test]
async fn nested_catches_forward_each_original_logger_failure_to_the_next_owner() -> AuthResult<()> {
    for pending in [false, true] {
        for retained in [false, true] {
            for recover in [false, true] {
                let errors = Errors::new();
                let events = Arc::new(Mutex::new(Vec::new()));
                let logger = Logger::new(FieldObject::from(FieldMap::from([
                    ("level".into(), "error".into()),
                    ("disableColors".into(), true.into()),
                    (
                        "log".into(),
                        FieldFunction::contextual({
                            let errors = errors.clone();
                            let events = events.clone();
                            move |_, arguments| {
                                let mut events = events.lock();
                                let (message, original, replacement) = if events.is_empty() {
                                    (CUSTOM, "task", "taskLogger")
                                } else {
                                    (SHARED, "taskLogger", "handlerLogger")
                                };
                                assert_eq!(arguments.len(), 3);
                                assert!(arguments[1].strict_equals(&message.into()));
                                assert!(arguments[2].strict_equals(&errors.value(original)?));
                                events.push((message, errors.identity(&arguments[2])?));
                                if recover && replacement == "handlerLogger" {
                                    Ok(FieldValue::Undefined)
                                } else {
                                    Err(AuthError::from_thrown(errors.value(replacement)?))
                                }
                            }
                        })
                        .into(),
                    ),
                ])))?;
                let tasks = Arc::new(Mutex::new(Vec::<BackgroundTask>::new()));
                let handler = retained.then(|| {
                    BackgroundTasks::new({
                        let tasks = tasks.clone();
                        move |task| {
                            tasks.lock().push(task);
                            Ok(())
                        }
                    })
                });
                let gate = Arc::new(tokio::sync::Notify::new());
                let task: BackgroundFuture = Box::pin({
                    let gate = gate.clone();
                    let error = errors.value("task")?;
                    async move {
                        if pending {
                            gate.notified().await;
                        }
                        Err(AuthError::from_thrown(error))
                    }
                });
                let mut call = Box::pin(run_or_await_with_error_message(
                    Some(task),
                    handler.as_ref(),
                    &logger,
                    CUSTOM,
                ));
                let first = std::future::poll_fn(|cx| Poll::Ready(call.as_mut().poll(cx))).await;
                if pending {
                    assert!(events.lock().is_empty());
                }
                gate.notify_one();
                let result = match first {
                    Poll::Ready(result) => result,
                    Poll::Pending => call.await,
                };
                let actual = if retained {
                    assert_eq!(
                        outcome(result, &errors)?,
                        json!({"status":"fulfilled","value":{"type":"undefined"}})
                    );
                    let task = tasks
                        .lock()
                        .pop()
                        .ok_or_else(|| AuthError::internal("Handler did not retain task"))?;
                    task.await.map_err(|error| {
                        AuthError::internal(format!("Unexpected join failure: {error}"))
                    })?
                } else {
                    result
                };
                let expected = if recover {
                    json!({"status":"fulfilled","value":{"type":"undefined"}})
                } else {
                    errors.rejection(&errors.value("handlerLogger")?)?
                };
                assert_eq!(outcome(actual, &errors)?, expected);
                assert_eq!(
                    *events.lock(),
                    vec![
                        (CUSTOM, errors.identity(&errors.value("task")?)?),
                        (SHARED, errors.identity(&errors.value("taskLogger")?)?),
                    ]
                );
            }
        }
    }
    Ok(())
}

#[tokio::test]
async fn direct_background_catch_layers_keep_handler_errors_outside_the_task() -> AuthResult<()> {
    let errors = Errors::new();
    let events = Arc::new(Mutex::new(Vec::new()));
    let logger = Logger::new(FieldObject::from(FieldMap::from([(
        "log".into(),
        FieldFunction::contextual({
            let errors = errors.clone();
            let events = events.clone();
            move |_, arguments| {
                let mut events = events.lock();
                let name = if events.len() == 1 {
                    "task"
                } else {
                    "taskLogger"
                };
                assert_eq!(arguments.len(), 3);
                assert!(arguments[1].strict_equals(&"Failed to delete expired API keys:".into()));
                assert!(arguments[2].strict_equals(&errors.value(name)?));
                events.push(name);
                Err(AuthError::from_thrown(errors.value(if name == "task" {
                    "taskLogger"
                } else {
                    "handlerLogger"
                })?))
            }
        })
        .into(),
    )])))?;
    let tasks = Arc::new(Mutex::new(Vec::<BackgroundTask>::new()));
    let handler = BackgroundTasks::new({
        let tasks = tasks.clone();
        let events = events.clone();
        let errors = errors.clone();
        move |task| {
            tasks.lock().push(task);
            events.lock().push("handler");
            Err(AuthError::from_thrown(errors.value("handler")?))
        }
    });
    let error = errors.value("task")?;
    let current = run_in_background_with_error_messages(
        Box::pin(async move { Err(AuthError::from_thrown(error)) }),
        Some(&handler),
        &logger,
        &[
            "Failed to delete expired API keys:",
            "Failed to delete expired API keys:",
        ],
    )
    .await;
    assert_eq!(
        outcome(current, &errors)?,
        errors.rejection(&errors.value("handler")?)?
    );
    let task = tasks
        .lock()
        .pop()
        .ok_or_else(|| AuthError::internal("Handler did not retain task"))?;
    let result = task
        .await
        .map_err(|error| AuthError::internal(format!("Unexpected join failure: {error}")))?;
    assert_eq!(
        outcome(result, &errors)?,
        errors.rejection(&errors.value("handlerLogger")?)?
    );
    assert_eq!(*events.lock(), ["handler", "task", "taskLogger"]);
    Ok(())
}
