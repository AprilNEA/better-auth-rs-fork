use crate::{AuthResult, FieldValue};
use parking_lot::Mutex;
use std::sync::Arc;

#[derive(Debug)]
struct ParsedBody {
    source: Option<Vec<u8>>,
    value: FieldValue,
}

/// Clones share the first decode. Replacing bytes detaches only the changed request.
#[derive(Debug, Default)]
pub(crate) struct RequestBodyCache {
    parsed: Mutex<Arc<Mutex<Option<ParsedBody>>>>,
}

impl Clone for RequestBodyCache {
    fn clone(&self) -> Self {
        Self {
            parsed: Mutex::new(self.parsed.lock().clone()),
        }
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
        let mut slot = self.parsed.lock();
        let mut parsed = slot.lock();
        if let Some(parsed) = parsed.as_ref().filter(|parsed| &parsed.source == source) {
            return Ok(parsed.value.clone());
        }
        let value = source
            .as_deref()
            .filter(|bytes| !bytes.is_empty())
            .map(serde_json::from_slice::<serde_json::Value>)
            .transpose()?
            .map(FieldValue::from)
            .unwrap_or_default();
        let body = ParsedBody {
            source: source.clone(),
            value: value.clone(),
        };
        if parsed.is_none() {
            *parsed = Some(body);
        } else {
            drop(parsed);
            *slot = Arc::new(Mutex::new(Some(body)));
        }
        Ok(value)
    }
}
