use super::*;

fn success_value(kind: &str) -> AuthResult<FieldValue> {
    match kind {
        "undefined" => Ok(FieldValue::Undefined),
        "null" => Ok(FieldValue::Null),
        "object" => Ok(values::with_hidden_property(
            FieldMap::from([
                ("marker".into(), "producer-result".into()),
                ("missing".into(), FieldValue::Undefined),
                ("nullable".into(), FieldValue::Null),
                (
                    "nested".into(),
                    FieldMap::from([("token".into(), "retained".into())]).into(),
                ),
                (
                    "hidden".into(),
                    FieldMap::from([("token".into(), "non-enumerable".into())]).into(),
                ),
            ]),
            "hidden",
        )),
        _ => Err(AuthError::internal("Unknown background completion value")),
    }
}

fn snapshot(trace: &Trace, current: &Json, tasks: &[Json], value: &FieldValue) -> AuthResult<Json> {
    Ok(json!({
        "rawState":trace.raw_state,"currentCall":current,"taskStates":tasks,
        "value":native_shape(value)?,
    }))
}

fn expected_snapshot(source: &Json) -> AuthResult<Json> {
    let tasks = source["taskStates"]
        .as_array()
        .ok_or_else(|| AuthError::internal("Success fixture has no task states"))?
        .iter()
        .map(projected_state)
        .collect::<AuthResult<Vec<_>>>()?;
    Ok(json!({
        "rawState":source["rawState"],"currentCall":projected_state(&source["currentCall"])?,
        "taskStates":tasks,"value":source_shape(&source["value"])?,
    }))
}

fn expected_events(source: &Json) -> AuthResult<Vec<Json>> {
    let mut events = Vec::new();
    for event in source
        .as_array()
        .ok_or_else(|| AuthError::internal("Success fixture has no events"))?
    {
        match event["phase"].as_str() {
            Some("task:start" | "task:resume" | "gate:release") => events.push(event.clone()),
            Some("task:fulfill") => {
                let mut event = event.clone();
                event["value"] = source_shape(&event["value"])?;
                events.push(event);
            }
            Some("handler:received") => {
                events.push(json!({"phase":"handler:received","index":event["index"]}));
            }
            // Promise invocation and reaction order remain in the source fixture.
            Some("call:returned" | "call:fulfilled" | "owned-task:fulfilled") => {}
            phase => {
                return Err(AuthError::internal(format!(
                    "Unclassified completion event: {phase:?}"
                )));
            }
        }
    }
    Ok(events)
}

async fn retained_state(task: BackgroundTask, original: &FieldValue) -> AuthResult<Json> {
    let value = task
        .await
        .map_err(|error| AuthError::internal(format!("Unexpected task join failure: {error}")))??;
    Ok(json!({
        "status":"fulfilled","value":native_shape(&value)?,
        "sameOriginal":value.strict_equals(original),
    }))
}

async fn run_case(case: &Json) -> AuthResult<()> {
    let name = case["name"]
        .as_str()
        .ok_or_else(|| AuthError::internal("Missing completion case name"))?;
    let original = success_value(
        case["value"]
            .as_str()
            .ok_or_else(|| AuthError::internal("Missing completion value kind"))?,
    )?;
    let before = native_shape(&original)?;
    assert_replay(&before, &source_shape(&case["valueBefore"])?, name);
    let trace = Arc::new(Mutex::new(Trace::default()));
    let logger = Logger::new(FieldObject::from(FieldMap::from([
        ("level".into(), "error".into()),
        ("disableColors".into(), true.into()),
        (
            "log".into(),
            FieldFunction::contextual({
                let trace = trace.clone();
                move |_, arguments| {
                    assert!(arguments.len() >= 2);
                    trace.lock().logs.push(json!({
                        "level":arguments[0].json()?,"message":arguments[1].json()?,
                        "arguments":native_shape(&arguments[2..].to_vec().into())?,
                    }));
                    Ok(FieldValue::Undefined)
                }
            })
            .into(),
        ),
    ])))?;
    let retained = Arc::new(Mutex::new(Vec::<BackgroundTask>::new()));
    let handler = (case["handler"] == "retain").then(|| {
        let retained = retained.clone();
        let trace = trace.clone();
        BackgroundTasks::new(move |task| {
            let mut retained = retained.lock();
            let index = retained.len();
            retained.push(task);
            trace
                .lock()
                .record("handler:received", json!({"index":index}));
            Ok(())
        })
    });
    let gate = Arc::new(tokio::sync::Notify::new());
    let pending = case["timing"] == "pending";
    let task = BackgroundFuture::native({
        let value = original.clone();
        let trace = trace.clone();
        let gate = gate.clone();
        async move {
            {
                let mut trace = trace.lock();
                trace.raw_state = "started";
                trace.record("task:start", json!({}));
            }
            if pending {
                gate.notified().await;
                trace.lock().record("task:resume", json!({}));
            }
            let mut trace = trace.lock();
            trace.raw_state = "fulfillment-produced";
            trace.record("task:fulfill", json!({"value":native_shape(&value)?}));
            Ok(value)
        }
    });
    let mut call = Box::pin(async {
        if case["primitive"] == "runInBackground" {
            run_in_background_with_error_messages(task, handler.as_ref(), &logger, &[]).await
        } else {
            run_or_await(Some(task), handler.as_ref(), &logger).await
        }
    });
    let complete = json!({"status":"fulfilled","value":{"type":"undefined"}});
    let mut current = json!({"status":"pending"});
    let first = std::future::poll_fn(|context| Poll::Ready(call.as_mut().poll(context))).await;
    let call_pending = first.is_pending();
    if let Poll::Ready(result) = first {
        result?;
        current = complete.clone();
    }
    let mut tasks = std::mem::take(&mut *retained.lock());
    let mut task_states = vec![json!({"status":"pending"}); tasks.len()];
    if pending {
        for task in &mut tasks {
            assert!(
                std::future::poll_fn(|context| Poll::Ready(Pin::new(&mut *task).poll(context)))
                    .await
                    .is_pending()
            );
        }
    } else {
        for (index, task) in tasks.drain(..).enumerate() {
            task_states[index] = retained_state(task, &original).await?;
        }
    }
    assert_replay(
        &snapshot(&trace.lock(), &current, &task_states, &original)?,
        &expected_snapshot(&case["beforeRelease"])?,
        name,
    );
    trace.lock().record("gate:release", json!({}));
    gate.notify_one();
    if call_pending {
        call.await?;
        current = complete;
    }
    for (index, task) in tasks.drain(..).enumerate() {
        task_states[index] = retained_state(task, &original).await?;
    }
    let trace = trace.lock();
    assert_replay(
        &snapshot(&trace, &current, &task_states, &original)?,
        &expected_snapshot(&case["afterSettlement"])?,
        name,
    );
    assert_replay(
        &trace.observer.events.clone().into(),
        &expected_events(&case["events"])?.into(),
        name,
    );
    assert_replay(&trace.logs.clone().into(), &case["logs"], name);
    assert_replay(
        &trace.observer.function_ids().into(),
        &case["functions"],
        name,
    );
    assert_replay(
        &native_shape(&original)?,
        &source_shape(&case["valueAfter"])?,
        name,
    );
    assert_eq!(before, native_shape(&original)?);
    Ok(())
}

#[tokio::test]
async fn background_success_values_match_frozen_source_cases() -> AuthResult<()> {
    let fixture: Json = serde_json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../tests/fixtures/background-success-values-1.7.6.json"
    )))?;
    assert_eq!(fixture["contract"], "background-success-values");
    assert_eq!(fixture["version"], "1.7.6");
    let cases = fixture["cases"]
        .as_array()
        .ok_or_else(|| AuthError::internal("Missing completion cases"))?;
    let expected_names = ["ready", "pending"]
        .into_iter()
        .flat_map(|timing| {
            ["undefined", "null", "object"]
                .into_iter()
                .flat_map(move |value| {
                    [
                        ("runInBackgroundOrAwait", "none"),
                        ("runInBackgroundOrAwait", "retain"),
                        ("runInBackground", "retain"),
                    ]
                    .into_iter()
                    .map(move |(primitive, handler)| {
                        format!("{primitive}/{handler}/{timing}/{value}")
                    })
                })
        })
        .collect::<Vec<_>>();
    assert_eq!(
        cases
            .iter()
            .map(|case| case["name"].as_str().unwrap_or_default())
            .collect::<Vec<_>>(),
        expected_names,
    );
    for case in cases {
        tokio::time::timeout(std::time::Duration::from_secs(5), run_case(case))
            .await
            .map_err(|_| {
                AuthError::internal(format!("Completion case did not settle: {}", case["name"]))
            })??;
    }
    Ok(())
}

#[tokio::test]
async fn unit_notifications_complete_with_undefined() -> AuthResult<()> {
    let retained = Arc::new(Mutex::new(None));
    let handler = BackgroundTasks::new({
        let retained = retained.clone();
        move |task| {
            *retained.lock() = Some(task);
            Ok(())
        }
    });
    let logger = Logger::new(crate::observability::LoggerConfig::default())?;
    run_or_await(
        Some(BackgroundFuture::new(async { Ok(()) })),
        Some(&handler),
        &logger,
    )
    .await?;
    let task = retained
        .lock()
        .take()
        .ok_or_else(|| AuthError::internal("Handler did not retain task"))?;
    let value = task
        .await
        .map_err(|error| AuthError::internal(format!("Unexpected task join failure: {error}")))??;
    assert!(value.is_undefined());
    Ok(())
}
