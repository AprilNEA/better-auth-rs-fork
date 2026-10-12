use super::*;

pub(super) struct Storage {
    cache: Mutex<indexmap::IndexMap<String, FieldValue>>,
    observer: Observer,
    references: Vec<FieldValue>,
    concurrent: FieldValue,
    batch: bool,
    reads: Mutex<usize>,
}

impl Storage {
    pub(super) fn new(
        scenario: &Json,
        values: &values::Values,
        observer: Observer,
    ) -> AuthResult<Self> {
        let mut cache =
            indexmap::IndexMap::from([(INDEX.into(), values.initial_index.clone().into())]);
        for (token, expiration) in [
            ("target", 60_000),
            ("retained", 90_000),
            ("expired", -1_000),
            ("concurrent", 180_000),
        ] {
            let mut envelope = FieldMap::from([
                ("session".into(), session(token, expiration).into()),
                ("user".into(), user().into()),
            ]);
            if token == "target" {
                let _ = envelope.insert("discardedEnvelopeField".into(), "before".into());
            }
            let _ = cache.insert(
                token.into(),
                FieldValue::from(envelope).stringify()?.unwrap().into(),
            );
        }
        if let Some(root) = values.roots.get("root") {
            let _ = cache.insert(INDEX.into(), root.clone());
        }
        if let Some(envelope) = values.roots.get("envelope") {
            let _ = cache.insert("target".into(), envelope.clone());
        }
        if let Some(reference) = values.roots.get("reference") {
            let _ = cache.insert(INDEX.into(), vec![reference.clone()].into());
        }
        Ok(Self {
            cache: Mutex::new(cache),
            observer,
            references: values.references.clone(),
            concurrent: values.concurrent.clone(),
            batch: scenario["operation"] == "batch-delete",
            reads: Mutex::new(0),
        })
    }

    pub(super) fn value(&self, key: &str) -> FieldValue {
        self.cache
            .lock()
            .unwrap()
            .get(key)
            .cloned()
            .unwrap_or(FieldValue::Null)
    }

    pub(super) fn snapshot(&self) -> FieldValue {
        self.cache
            .lock()
            .unwrap()
            .iter()
            .map(|(key, value)| FieldValue::from(vec![key.clone().into(), value.clone()]))
            .collect::<Vec<_>>()
            .into()
    }
}

#[async_trait]
impl SecondaryStorage for Storage {
    async fn get(&self, key: &str) -> AuthResult<Option<Json>> {
        self.get_native(&key.into())
            .await?
            .map(|value| value.json())
            .transpose()
            .map(Option::flatten)
    }

    async fn get_native(&self, key: &FieldValue) -> AuthResult<Option<FieldValue>> {
        let key = key.display_utf16()?.to_utf8().unwrap();
        if key == INDEX {
            let mut reads = self.reads.lock().unwrap();
            *reads += 1;
            if *reads == 2 && self.batch {
                let mut references = self.references.clone();
                references.push(self.concurrent.clone());
                let value: FieldValue = FieldValue::from(references).stringify()?.unwrap().into();
                let _ = self
                    .cache
                    .lock()
                    .unwrap()
                    .insert(key.clone(), value.clone());
                let mut observer = self.observer.lock().unwrap();
                let value = observer.observe(&value)?;
                observer.record("concurrent:index-replacement", [("value".into(), value)]);
            }
        }
        let value = self.value(&key);
        let mut observer = self.observer.lock().unwrap();
        let observed = observer.observe(&value)?;
        observer.record(
            "cache.get",
            [("key".into(), key.into()), ("value".into(), observed)],
        );
        Ok(Some(value))
    }

    async fn set_native(
        &self,
        key: &FieldValue,
        value: &FieldValue,
        ttl: Option<f64>,
    ) -> AuthResult<()> {
        let key = key.display_utf16()?.to_utf8().unwrap();
        let mut observer = self.observer.lock().unwrap();
        let observed = observer.observe(value)?;
        let ttl = observer.observe(&ttl.map_or(FieldValue::Undefined, FieldValue::from))?;
        observer.record(
            "cache.set",
            [
                ("key".into(), key.clone().into()),
                ("value".into(), observed),
                ("ttl".into(), ttl),
            ],
        );
        let _ = self.cache.lock().unwrap().insert(key, value.clone());
        Ok(())
    }

    async fn delete(&self, key: &str) -> AuthResult<()> {
        self.observer
            .lock()
            .unwrap()
            .record("cache.delete", [("key".into(), key.into())]);
        let _ = self.cache.lock().unwrap().shift_remove(key);
        Ok(())
    }

    async fn get_and_delete(&self, key: &str) -> AuthResult<Option<Json>> {
        let value = self.get(key).await?;
        self.delete(key).await?;
        Ok(value)
    }
}
