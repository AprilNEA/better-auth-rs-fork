#![expect(
    clippy::panic_in_result_fn,
    clippy::indexing_slicing,
    reason = "The contract validates callback lengths and retained task counts before comparing original errors and exact order."
)]

use super::*;
use crate::{AuthError, FieldFunction, FieldMap, FieldObject, FieldValue};
use parking_lot::Mutex;
use serde_json::{Value as Json, json};

mod catches;
mod completion;
#[path = "../../../../tests/support/secondary_native_observation.rs"]
mod observation;
mod values;

use observation::{NativeObservation, assert_replay};
use values::{Errors, native_shape, source_shape};

const SHARED: &str = "Failed to run background task:";
const CUSTOM: &str = "Caller task failed:";

struct Trace {
    observer: NativeObservation,
    logs: Vec<Json>,
    raw_state: &'static str,
    started: usize,
    mutations: Vec<Json>,
    continued: usize,
    input_catch: Json,
}

impl Default for Trace {
    fn default() -> Self {
        Self {
            observer: NativeObservation::default(),
            logs: Vec::new(),
            raw_state: "not-started",
            started: 0,
            mutations: Vec::new(),
            continued: 0,
            input_catch: json!({"status":"not-entered"}),
        }
    }
}

impl Trace {
    fn record(&mut self, phase: &str, fields: Json) {
        self.observer.record(
            phase,
            fields
                .as_object()
                .into_iter()
                .flat_map(|fields| fields.clone()),
        );
    }
}

fn outcome(result: AuthResult<()>, errors: &Errors) -> AuthResult<Json> {
    task_outcome(result.map(|()| FieldValue::Undefined), errors)
}

fn task_outcome(result: AuthResult<FieldValue>, errors: &Errors) -> AuthResult<Json> {
    match result {
        Ok(value) => Ok(json!({"status":"fulfilled","value":native_shape(&value)?})),
        Err(error) => errors.rejection(&error.into_thrown_value()?),
    }
}

fn projected_state(source: &Json) -> AuthResult<Json> {
    let mut state = source.clone();
    for key in ["error", "value"] {
        if let Some(value) = state.get_mut(key) {
            *value = source_shape(value)?;
        }
    }
    Ok(state)
}

fn snapshot(trace: &Trace, current: &Json, tasks: &[Json]) -> Json {
    json!({
        "currentCall":current,"taskStates":tasks,"rawProducerState":trace.raw_state,
        "inputCatchState":trace.input_catch,
        "application":{"started":trace.started,"mutations":trace.mutations,"currentCallContinued":trace.continued},
    })
}

fn expected_snapshot(source: &Json) -> AuthResult<Json> {
    let tasks = source["taskStates"]
        .as_array()
        .ok_or_else(|| AuthError::internal("Background fixture has no task states"))?
        .iter()
        .map(projected_state)
        .collect::<AuthResult<Vec<_>>>()?;
    Ok(json!({
        "currentCall":projected_state(&source["currentCall"])? ,
        "taskStates":tasks,"rawProducerState":source["rawProducerState"],
        "inputCatchState":projected_state(&source["inputCatchState"])? ,
        "application":source["application"],
    }))
}

fn expected_events(source: &Json) -> AuthResult<Vec<Json>> {
    let mut events = Vec::new();
    for event in source
        .as_array()
        .ok_or_else(|| AuthError::internal("Background fixture has no events"))?
    {
        match event["phase"].as_str() {
            Some("handler:received") => {
                events.push(json!({"phase":"handler:received","index":event["index"]}));
            }
            Some(
                "task:start" | "task:resume" | "task:reject" | "handler:throw" | "handler:return"
                | "logger:call" | "logger:throw" | "logger:return" | "gate:release",
            ) => {
                let mut event = event.clone();
                for key in ["error", "arguments"] {
                    if let Some(value) = event.get_mut(key) {
                        *value = source_shape(value)?;
                    }
                }
                events.push(event);
            }
            // JavaScript invocation, Promise reactions, and host checkpoints have no Rust host equivalent.
            Some(
                "call:start"
                | "call:returned"
                | "call:fulfilled"
                | "call:rejected"
                | "call:threw-synchronously"
                | "owned-task:fulfilled"
                | "owned-task:rejected"
                | "input-catch:entered"
                | "input-catch:throw"
                | "host:checkpoint",
            ) => {}
            phase => {
                return Err(AuthError::internal(format!(
                    "Unclassified source event: {phase:?}"
                )));
            }
        }
    }
    Ok(events)
}

async fn run_case(case: &Json) -> AuthResult<()> {
    let name = case["name"]
        .as_str()
        .ok_or_else(|| AuthError::internal("Missing case name"))?;
    let direct = case["primitive"] == "runInBackground";
    let pending = case["timing"] == "pending";
    let handler_kind = case["handler"]
        .as_str()
        .ok_or_else(|| AuthError::internal("Missing handler"))?;
    let failure = case["loggerFailure"]
        .as_str()
        .ok_or_else(|| AuthError::internal("Missing failure"))?
        .to_owned();
    let errors = Errors::new();
    let errors_before = native_shape(&errors.values)?;
    assert_replay(&errors_before, &source_shape(&case["errorsBefore"])?, name);
    let trace = Arc::new(Mutex::new(Trace::default()));
    let finished = Arc::new(tokio::sync::Notify::new());
    let logger_options: FieldObject = FieldMap::from([
        ("level".into(), "error".into()),
        ("disableColors".into(), true.into()),
    ])
    .into();
    let expected_owner: FieldValue = logger_options.clone().into();
    logger_options.set("log", FieldFunction::contextual({
        let errors = errors.clone();
        let trace = trace.clone();
        let finished = finished.clone();
        move |receiver, arguments| {
            assert_eq!(arguments.len(), 3);
            assert!(arguments[0].strict_equals(&"error".into()));
            assert!(arguments[1].strict_equals(&if direct { CUSTOM } else { SHARED }.into()));
            let error = &arguments[2];
            let owner = if error.strict_equals(&errors.value("task")?) { "task" } else { "handler" };
            assert!(error.strict_equals(&errors.value(owner)?));
            let log = json!({"level":"error","message":arguments[1].json()?,
                "arguments":native_shape(&arguments[2..].to_vec().into())?,
                "identity":errors.identity(error)?,"sameReceiver":receiver.strict_equals(&expected_owner)});
            let mut trace = trace.lock();
            let mut fields = serde_json::Map::from_iter([("index".into(), trace.logs.len().into())]);
            fields.extend(log.as_object().into_iter().flat_map(|fields| fields.clone()));
            trace.logs.push(log);
            trace.record("logger:call", fields.into());
            if failure == owner || failure == "both" {
                let error = errors.value(&format!("{owner}Logger"))?;
                trace.record("logger:throw", json!({"identity":errors.identity(&error)?,"error":native_shape(&error)?}));
                if direct { trace.input_catch = errors.rejection(&error)?; }
                if owner == "task" { finished.notify_one(); }
                return Err(AuthError::from_thrown(error));
            }
            trace.record("logger:return", json!({"result":{"type":"undefined"}}));
            if direct { trace.input_catch = json!({"status":"fulfilled","value":{"type":"undefined"}}); }
            if owner == "task" { finished.notify_one(); }
            Ok(FieldValue::Undefined)
        }
    }).into())?;
    let logger = Logger::new(logger_options)?;
    let retained = Arc::new(Mutex::new(Vec::<BackgroundTask>::new()));
    let handler = (handler_kind != "none").then(|| {
        let retained = retained.clone();
        let trace = trace.clone();
        let errors = errors.clone();
        let throws = handler_kind == "throw";
        BackgroundTasks::new(move |task| {
            let index = retained.lock().len();
            retained.lock().push(task);
            let mut trace = trace.lock();
            trace.record("handler:received", json!({"index":index}));
            if throws {
                let error = errors.value("handler")?;
                trace.record(
                    "handler:throw",
                    json!({"identity":errors.identity(&error)?,"error":native_shape(&error)?}),
                );
                Err(AuthError::from_thrown(error))
            } else {
                trace.record("handler:return", json!({"result":{"type":"undefined"}}));
                Ok(())
            }
        })
    });
    let gate = Arc::new(tokio::sync::Notify::new());
    let task = BackgroundFuture::new({
        let trace = trace.clone();
        let errors = errors.clone();
        let gate = gate.clone();
        async move {
            {
                let mut trace = trace.lock();
                trace.started += 1;
                trace.raw_state = "started";
                trace.record("task:start", json!({}));
            }
            if pending {
                gate.notified().await;
                trace.lock().record("task:resume", json!({}));
            }
            let error = errors.value("task")?;
            let mut trace = trace.lock();
            trace
                .mutations
                .push(json!({"phase":"before-reject","value":"persisted"}));
            trace.raw_state = "rejection-produced";
            trace.record(
                "task:reject",
                json!({"identity":errors.identity(&error)?,"error":native_shape(&error)?}),
            );
            Err(AuthError::from_thrown(error))
        }
    });
    let mut call = Box::pin(async {
        if direct {
            run_in_background_with_error_message(task, handler.as_ref(), &logger, CUSTOM).await
        } else {
            run_or_await(Some(task), handler.as_ref(), &logger).await
        }
    });
    let mut current = json!({"status":"pending"});
    let first = std::future::poll_fn(|cx| Poll::Ready(call.as_mut().poll(cx))).await;
    let call_pending = first.is_pending();
    if let Poll::Ready(result) = first {
        if result.is_ok() {
            trace.lock().continued += 1;
        }
        current = outcome(result, &errors)?;
    }
    let mut tasks = std::mem::take(&mut *retained.lock());
    let mut task_states = vec![json!({"status":"pending"}); tasks.len()];
    if !pending {
        for (index, task) in tasks.drain(..).enumerate() {
            task_states[index] = task_outcome(
                task.await.map_err(|error| {
                    AuthError::internal(format!("Unexpected task join failure: {error}"))
                })?,
                &errors,
            )?;
        }
    }
    assert_replay(
        &snapshot(&trace.lock(), &current, &task_states),
        &expected_snapshot(&case["beforeRelease"])?,
        name,
    );
    trace.lock().record("gate:release", json!({}));
    gate.notify_one();
    if call_pending {
        let result = call.await;
        if result.is_ok() {
            trace.lock().continued += 1;
        }
        current = outcome(result, &errors)?;
    }
    for (index, task) in tasks.drain(..).enumerate() {
        task_states[index] = task_outcome(
            task.await.map_err(|error| {
                AuthError::internal(format!("Unexpected task join failure: {error}"))
            })?,
            &errors,
        )?;
    }
    finished.notified().await;
    let trace = trace.lock();
    assert_replay(
        &snapshot(&trace, &current, &task_states),
        &expected_snapshot(&case["afterSettlement"])?,
        name,
    );
    assert_replay(
        &trace.observer.events.clone().into(),
        &expected_events(&case["events"])?.into(),
        name,
    );
    let mut expected_logs = case["logs"].clone();
    for log in expected_logs
        .as_array_mut()
        .ok_or_else(|| AuthError::internal("Missing source logs"))?
    {
        log["arguments"] = source_shape(&log["arguments"])?;
    }
    assert_replay(&trace.logs.clone().into(), &expected_logs, name);
    assert_replay(
        &native_shape(&errors.values)?,
        &source_shape(&case["errorsAfter"])?,
        name,
    );
    assert_eq!(errors_before, native_shape(&errors.values)?);
    assert_replay(
        &trace.observer.function_ids().into(),
        &case["functions"],
        name,
    );
    assert_eq!(
        case["hostEvents"],
        json!([]),
        "Source host evidence remains unchanged; Rust does not implement the JavaScript host lifecycle"
    );
    Ok(())
}

#[tokio::test]
async fn background_logger_task_ownership_matches_frozen_source_cases() -> AuthResult<()> {
    let fixture: Json = serde_json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../tests/fixtures/logger-background-ownership-1.7.6.json"
    )))?;
    assert_eq!(fixture["version"], "1.7.6");
    let cases = fixture["cases"]
        .as_array()
        .ok_or_else(|| AuthError::internal("Missing background cases"))?;
    assert_eq!(cases.len(), 16);
    for case in cases {
        tokio::time::timeout(std::time::Duration::from_secs(5), run_case(case))
            .await
            .map_err(|_| {
                AuthError::internal(format!("Background case did not settle: {}", case["name"]))
            })??;
    }
    Ok(())
}
