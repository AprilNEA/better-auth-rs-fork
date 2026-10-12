use crate::{AuthResult, FieldValue};
use parking_lot::Mutex;
use serde_json::Value;
use std::sync::Arc;

#[derive(Debug)]
struct ParsedInput<Source> {
    source: Source,
    value: FieldValue,
}

/// Clones share the first decode. Replacing the source detaches only the changed request.
#[derive(Debug, Default)]
pub(crate) struct RequestInputCache<Source> {
    parsed: Mutex<Arc<Mutex<Option<ParsedInput<Source>>>>>,
}

pub(crate) type RequestBodyCache = RequestInputCache<Option<Vec<u8>>>;
pub(crate) type RequestQueryCache = RequestInputCache<Option<Value>>;

// JSON map equality ignores insertion order. Source guards must detect changes to native enumeration order.
pub(super) fn same_query_source(left: &Option<Value>, right: &Option<Value>) -> bool {
    match (left, right) {
        (Some(left), Some(right)) => same_json_source(left, right),
        (None, None) => true,
        _ => false,
    }
}

fn same_json_source(left: &Value, right: &Value) -> bool {
    match (left, right) {
        (Value::Object(left), Value::Object(right)) => {
            left.len() == right.len()
                && left
                    .iter()
                    .zip(right)
                    .all(|((left_key, left), (right_key, right))| {
                        left_key == right_key && same_json_source(left, right)
                    })
        }
        (Value::Array(left), Value::Array(right)) => {
            left.len() == right.len()
                && left
                    .iter()
                    .zip(right)
                    .all(|(left, right)| same_json_source(left, right))
        }
        (Value::Number(left), Value::Number(right)) => {
            left == right && left.as_f64().map(f64::to_bits) == right.as_f64().map(f64::to_bits)
        }
        _ => left == right,
    }
}

impl<Source> Clone for RequestInputCache<Source> {
    fn clone(&self) -> Self {
        Self {
            parsed: Mutex::new(self.parsed.lock().clone()),
        }
    }
}

impl<Source: Clone> RequestInputCache<Source> {
    fn read_with(
        &self,
        source: &Source,
        same_source: fn(&Source, &Source) -> bool,
        parse: impl FnOnce() -> AuthResult<FieldValue>,
    ) -> AuthResult<FieldValue> {
        let mut slot = self.parsed.lock();
        let mut parsed = slot.lock();
        if let Some(parsed) = parsed
            .as_ref()
            .filter(|parsed| same_source(&parsed.source, source))
        {
            return Ok(parsed.value.clone());
        }
        let value = parse()?;
        let input = ParsedInput {
            source: source.clone(),
            value: value.clone(),
        };
        if parsed.is_none() {
            *parsed = Some(input);
        } else {
            drop(parsed);
            *slot = Arc::new(Mutex::new(Some(input)));
        }
        Ok(value)
    }
}

impl RequestBodyCache {
    pub(super) fn cached(&self, source: &Option<Vec<u8>>) -> Option<FieldValue> {
        self.parsed
            .lock()
            .lock()
            .as_ref()
            .filter(|parsed| &parsed.source == source)
            .map(|parsed| parsed.value.clone())
    }

    pub(super) fn read(&self, source: &Option<Vec<u8>>) -> AuthResult<FieldValue> {
        self.read_with(source, PartialEq::eq, || {
            Ok(source
                .as_deref()
                .filter(|bytes| !bytes.is_empty())
                .map(serde_json::from_slice::<serde_json::Value>)
                .transpose()?
                .map(FieldValue::from)
                .unwrap_or_default())
        })
    }
}

impl RequestQueryCache {
    pub(super) fn read(&self, source: &Option<Value>) -> AuthResult<FieldValue> {
        self.read_with(source, same_query_source, || {
            Ok(source.clone().map(FieldValue::from).unwrap_or_default())
        })
    }
}
