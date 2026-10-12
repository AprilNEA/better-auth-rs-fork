use super::*;
use tracing::{
    Event, Metadata, Subscriber,
    field::{Field, Visit},
    span::{Attributes, Id, Record},
};

#[derive(Default)]
pub(super) struct Host {
    pub(super) events: Mutex<Vec<Value>>,
    pub(super) reported: Notify,
}

#[derive(Default)]
struct Fields(serde_json::Map<String, Value>);

impl Visit for Fields {
    fn record_str(&mut self, field: &Field, value: &str) {
        let _ = self.0.insert(field.name().into(), value.into());
    }

    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        let _ = self
            .0
            .insert(field.name().into(), format!("{value:?}").into());
    }
}

impl Subscriber for Host {
    fn enabled(&self, metadata: &Metadata<'_>) -> bool {
        matches!(metadata.target(), "better-auth::runtime" | "better-auth")
    }

    fn new_span(&self, _: &Attributes<'_>) -> Id {
        Id::from_u64(1)
    }
    fn record(&self, _: &Id, _: &Record<'_>) {}
    fn record_follows_from(&self, _: &Id, _: &Id) {}
    fn enter(&self, _: &Id) {}
    fn exit(&self, _: &Id) {}

    fn event(&self, event: &Event<'_>) {
        let mut fields = Fields::default();
        event.record(&mut fields);
        self.events.lock().unwrap().push(json!({
            "target":event.metadata().target(),"fields":fields.0,
        }));
        self.reported.notify_one();
    }
}
