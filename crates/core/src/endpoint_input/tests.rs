#![expect(
    clippy::panic_in_result_fn,
    reason = "Regressions assert request identity, getter scheduling, and cache invalidation."
)]

use super::ValidatedBody;
use crate::{
    AuthError, AuthRequest, AuthResult, FieldMap, FieldObject, FieldValue, HttpMethod,
    field_value::{FieldObjectSource, FieldPropertyDescriptor},
    hooks::RequestHookContext,
};
use serde_json::{Value, json};
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

fn object(value: &FieldValue) -> AuthResult<&FieldObject> {
    value
        .as_object()
        .ok_or_else(|| AuthError::internal("Expected input object"))
}

fn request(mode: &str) -> AuthResult<AuthRequest> {
    let mut request = AuthRequest::new(HttpMethod::Post, "/input");
    request.body = Some(br#"{ "name": "before", "metadata": { "value": 1 } }"#.to_vec());
    match mode {
        "http-json" => {
            let _ = request
                .headers
                .insert("content-type".into(), "application/json".into());
            request.parse_http_body(&["application/json".into()])?;
        }
        "http-form" => {
            request.body = Some(b"name=before&metadata=raw".to_vec());
            let _ = request.headers.insert(
                "content-type".into(),
                "application/x-www-form-urlencoded".into(),
            );
            request.parse_http_body(&["application/x-www-form-urlencoded".into()])?;
        }
        "json-projection" => request.set_endpoint_body(ValidatedBody::new(
            Some(json!({"name": "before", "metadata": {"value": 1}})),
            "typed".to_owned(),
        )),
        _ => (),
    }
    Ok(request)
}

#[test]
fn input_reads_and_request_clones_share_one_live_projection() -> AuthResult<()> {
    for mode in ["raw", "http-json", "http-form", "json-projection"] {
        let request = request(mode)?;
        let before_read = request.clone();
        let bytes = request.body.clone();
        let first = request.input_field_value()?;
        assert!(first.strict_equals(&request.input_field_value()?), "{mode}");
        assert!(
            first.strict_equals(&before_read.input_field_value()?),
            "{mode}"
        );
        assert!(
            first.strict_equals(&request.clone().input_field_value()?),
            "{mode}"
        );
        let input = request.unvalidated_input()?;
        assert!(first.strict_equals(&input.field_value()), "{mode}");
        assert!(input.get::<String>().is_none());
        if mode == "json-projection" {
            assert_eq!(
                request.validated_body::<String>().map(String::as_str),
                Some("typed")
            );
        }
        let _ = object(&first)?.set("name", "after".into())?;
        let expected = if mode == "http-form" {
            json!({"name": "after", "metadata": "raw"})
        } else {
            json!({"name": "after", "metadata": {"value": 1}})
        };
        assert_eq!(request.input_body()?, Some(expected.clone()), "{mode}");
        assert_eq!(before_read.input_body()?, Some(expected.clone()), "{mode}");
        assert_eq!(request.body_as_json::<Value>()?, expected, "{mode}");
        assert_eq!(request.body, bytes, "{mode}");
        if let Some(snapshot) = request.parsed_http_body() {
            assert_eq!(snapshot.get("name"), Some(&json!("before")));
        }
    }
    Ok(())
}

#[test]
fn raw_replacement_detaches_cached_input_without_invalidating_other_clones() -> AuthResult<()> {
    for mode in ["raw", "http-json", "http-form", "json-projection"] {
        let mut request = request(mode)?;
        let unchanged = request.clone();
        let initial = request.input_field_value()?;
        let _ = object(&initial)?.set("name", "mutated".into())?;
        request.body = Some(br#"{"name":"replacement"}"#.to_vec());
        let replacement = request.input_field_value()?;
        assert!(!initial.strict_equals(&replacement), "{mode}");
        assert!(
            replacement.strict_equals(&request.input_field_value()?),
            "{mode}"
        );
        assert!(
            replacement.strict_equals(&request.clone().input_field_value()?),
            "{mode}"
        );
        assert!(
            initial.strict_equals(&unchanged.input_field_value()?),
            "{mode}"
        );
        assert_eq!(
            object(&unchanged.input_field_value()?)?.get("name")?,
            Some("mutated".into())
        );
        assert_eq!(
            request.input_body()?,
            Some(json!({"name": "replacement"})),
            "{mode}"
        );
        assert!(request.validated_body::<String>().is_none());
        assert!(request.parsed_http_body().is_none());
        request.body = Some(b"{".to_vec());
        assert!(request.input_field_value().is_err(), "{mode}");
        assert!(request.input_body().is_err(), "{mode}");
        assert!(
            initial.strict_equals(&unchanged.input_field_value()?),
            "{mode}"
        );
    }
    Ok(())
}

struct ReadProbe(AtomicUsize);

impl ReadProbe {
    fn reject<T>(&self) -> AuthResult<T> {
        let _ = self.0.fetch_add(1, Ordering::SeqCst);
        Err(AuthError::internal("Input property was read"))
    }
}

impl FieldObjectSource for ReadProbe {
    fn own_keys(&self) -> AuthResult<Vec<String>> {
        self.reject()
    }
    fn own_property_descriptor(&self, _: &str) -> AuthResult<Option<FieldPropertyDescriptor>> {
        self.reject()
    }
    fn get(&self, _: &str) -> AuthResult<Option<FieldValue>> {
        self.reject()
    }
    fn set(&self, _: String, _: FieldValue) -> AuthResult<Option<FieldValue>> {
        self.reject()
    }
    fn delete(&self, _: &str) -> AuthResult<Option<FieldValue>> {
        self.reject()
    }
    fn snapshot_fields(&self) -> AuthResult<FieldMap> {
        self.reject()
    }
    fn identity(&self) -> usize {
        std::ptr::from_ref(self) as usize
    }
}

#[test]
fn native_input_reads_and_hook_snapshots_do_not_traverse_getters() -> AuthResult<()> {
    let source = Arc::new(ReadProbe(AtomicUsize::new(0)));
    let value = FieldValue::Object(FieldObject::from_source(source.clone()));
    let validated = ValidatedBody::native(value.clone(), "typed".to_owned());
    assert!(value.strict_equals(&validated.field_value()));
    assert!(value.strict_equals(&validated.clone().field_value()));
    let mut request = AuthRequest::new(HttpMethod::Post, "/input");
    request.set_endpoint_body(validated);
    let clone = request.clone();
    assert!(value.strict_equals(&request.input_field_value()?));
    assert!(value.strict_equals(&request.input_field_value()?));
    assert!(value.strict_equals(&clone.input_field_value()?));
    assert!(value.strict_equals(&request.unvalidated_input()?.field_value()));
    let hook = RequestHookContext::from_request(&request)?;
    assert!(value.strict_equals(&hook.body));
    assert!(value.strict_equals(&hook.request.input_field_value()?));
    assert_eq!(
        request.validated_body::<String>().map(String::as_str),
        Some("typed")
    );
    assert_eq!(source.0.load(Ordering::SeqCst), 0);
    assert!(request.input_body().is_err());
    assert_eq!(source.0.load(Ordering::SeqCst), 1);
    assert!(value.strict_equals(&clone.input_field_value()?));
    assert_eq!(source.0.load(Ordering::SeqCst), 1);
    Ok(())
}

#[test]
fn raw_cache_preserves_http_policy_and_empty_body_json_errors() -> AuthResult<()> {
    let mut request = AuthRequest::new(HttpMethod::Post, "/input");
    request.body = Some(b"invalid=json".to_vec());
    let hook = RequestHookContext::from_request(&request)?;
    assert_eq!(hook.body, FieldValue::Undefined);
    assert!(request.parsed_http_body().is_none());
    request.body = Some(Vec::new());
    assert_eq!(request.input_field_value()?, FieldValue::Undefined);
    assert!(request.body_as_json::<Value>().is_err());
    Ok(())
}
