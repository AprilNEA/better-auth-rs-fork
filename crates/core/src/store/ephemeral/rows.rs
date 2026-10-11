//! Rows preserve object identity when a transaction commits into the live table.

use crate::{
    AuthError, AuthRecordFields, AuthResult, FieldMap, FieldValue, FromFieldMap, SchemaValue,
};
use std::hash::{Hash, Hasher};
use std::sync::{Arc, Mutex, MutexGuard};

use super::operation::MemoryGate;

pub(super) trait MemoryRow {
    fn id(&self) -> &SchemaValue<String>;
}

pub(super) struct RowRef<T>(pub(super) Arc<Mutex<T>>, pub(super) MemoryGate);

impl<T> Clone for RowRef<T> {
    fn clone(&self) -> Self {
        Self(self.0.clone(), self.1.clone())
    }
}

#[derive(Clone)]
pub(super) enum RecordSource {
    Live(RowRef<FieldMap>),
    LiveWithPatch(RowRef<FieldMap>, Box<FieldMap>),
    Snapshot(Box<FieldMap>),
}

impl RecordSource {
    pub(super) fn with_patch(self, patch: FieldMap) -> Self {
        if patch.is_empty() {
            return self;
        }
        match self {
            Self::Live(source) => Self::LiveWithPatch(source, Box::new(patch)),
            Self::LiveWithPatch(source, mut fields) => {
                fields.extend(patch);
                Self::LiveWithPatch(source, fields)
            }
            Self::Snapshot(mut fields) => {
                fields.extend(patch);
                Self::Snapshot(fields)
            }
        }
    }

    pub(super) fn joined(
        mut parent: FieldMap,
        relations: impl IntoIterator<Item = (String, FieldValue)>,
    ) -> Self {
        // Native adapters attach relations to a shallow parent copy before field output.
        parent.extend(relations);
        Self::Snapshot(Box::new(parent))
    }

    pub(super) fn field(&self, name: &str) -> AuthResult<Option<FieldValue>> {
        match self {
            Self::Live(source) => source.field(name),
            Self::LiveWithPatch(source, patch) => {
                let live = source.field(name)?;
                Ok(patch.get(name).cloned().or(live))
            }
            Self::Snapshot(record) => Ok(record.get(name).cloned()),
        }
    }

    pub(super) fn shallow_fields(&self) -> AuthResult<FieldMap> {
        match self {
            Self::Live(source) => source.shallow_fields(),
            Self::LiveWithPatch(source, patch) => {
                let mut fields = source.shallow_fields()?;
                fields.extend(
                    patch
                        .iter()
                        .map(|(name, value)| (name.clone(), value.clone())),
                );
                Ok(fields)
            }
            Self::Snapshot(record) => Ok((**record).clone()),
        }
    }
}

/// Read properties as shallow handles; implementations must not evaluate child values.
pub(super) trait ObjectRow:
    AuthRecordFields + FromFieldMap + Clone + Send + Sync + 'static
{
    fn property(&self, name: &str) -> AuthResult<Option<FieldValue>>;

    fn clone_hidden_values(&self) -> AuthResult<Vec<FieldValue>> {
        Ok(Vec::new())
    }

    fn with_cloned_fields(&self, fields: FieldMap, _state: Vec<FieldValue>) -> AuthResult<Self> {
        Self::from_field_values(fields)
    }
}

impl ObjectRow for FieldMap {
    fn property(&self, name: &str) -> AuthResult<Option<FieldValue>> {
        Ok(self.get(name).cloned())
    }
}

impl ObjectRow for crate::UserView {
    fn property(&self, name: &str) -> AuthResult<Option<FieldValue>> {
        Ok(self.field_values()?.get(name).cloned())
    }

    fn clone_hidden_values(&self) -> AuthResult<Vec<FieldValue>> {
        self.clone_hidden_values()
    }

    fn with_cloned_fields(&self, fields: FieldMap, state: Vec<FieldValue>) -> AuthResult<Self> {
        self.with_cloned_fields(fields, state)
    }
}

impl<T: ObjectRow> crate::field_value::FieldObjectSource for RowRef<T> {
    fn own_keys(&self) -> AuthResult<Vec<String>> {
        Ok(self.shallow_fields()?.keys().cloned().collect())
    }

    fn get(&self, name: &str) -> AuthResult<Option<FieldValue>> {
        self.field(name)
    }

    fn snapshot_fields(&self) -> AuthResult<FieldMap> {
        self.shallow_fields()
    }

    fn set(&self, name: String, value: FieldValue) -> AuthResult<Option<FieldValue>> {
        self.set_field(name, value)
    }

    fn delete(&self, name: &str) -> AuthResult<Option<FieldValue>> {
        self.delete_field(name)
    }

    fn identity(&self) -> usize {
        Arc::as_ptr(&self.0) as usize
    }

    fn as_any(&self) -> Option<&dyn std::any::Any> {
        Some(self)
    }

    fn clone_seed(&self) -> AuthResult<Option<crate::field_value::ObjectCloneSeed>> {
        let before = Arc::new(self.snapshot()?);
        let state = before.clone_hidden_values()?;
        let target = Self(Arc::new(Mutex::new((*before).clone())), self.1.clone());
        let object = crate::FieldObject::from_source(Arc::new(target.clone()));
        Ok(Some(crate::field_value::ObjectCloneSeed {
            object,
            state,
            original_record: Some(before.clone()),
            prepare: Box::new(move |fields, state| {
                let row = before.with_cloned_fields(fields, state)?;
                Ok(Box::new(move || {
                    crate::field_value::publish_clone(&target.0, row);
                }))
            }),
        }))
    }
}

impl<T: ObjectRow> RowRef<T> {
    pub(super) fn field(&self, name: &str) -> AuthResult<Option<FieldValue>> {
        let _operation = self.1.lock();
        lock(&self.0)?.property(name)
    }

    pub(super) fn shallow_fields(&self) -> AuthResult<FieldMap> {
        let _operation = self.1.lock();
        lock(&self.0)?.field_values()
    }

    pub(super) fn set_field(
        &self,
        name: String,
        value: FieldValue,
    ) -> AuthResult<Option<FieldValue>> {
        let _operation = self.1.lock();
        let mut fields = self.shallow_fields()?;
        let previous = fields.insert(name, value);
        fields.sort_property_order();
        self.replace(T::from_field_values(fields)?)?;
        Ok(previous)
    }

    pub(super) fn delete_field(&self, name: &str) -> AuthResult<Option<FieldValue>> {
        let _operation = self.1.lock();
        let mut fields = self.shallow_fields()?;
        let previous = fields.remove(name);
        self.replace(T::from_field_values(fields)?)?;
        Ok(previous)
    }

    pub(super) fn apply_patch(&self, patch: FieldMap) -> AuthResult<()> {
        let _operation = self.1.lock();
        let mut fields = self.shallow_fields()?;
        fields.extend(patch);
        fields.sort_property_order();
        self.replace(T::from_field_values(fields)?)
    }

    pub(super) fn increment_number_fields(&self, increments: &[(String, f64)]) -> AuthResult<()> {
        let _operation = self.1.lock();
        let mut fields = self.shallow_fields()?;
        for (name, delta) in increments {
            let previous = fields.get(name).and_then(FieldValue::as_f64).unwrap_or(0.0);
            let _ = fields.insert(name.clone(), (previous + delta).into());
        }
        fields.sort_property_order();
        self.replace(T::from_field_values(fields)?)
    }
}

impl<T: ObjectRow> RowRef<T> {
    pub(super) fn field_value(&self) -> FieldValue {
        FieldValue::Object(crate::FieldObject::from_source(Arc::new(self.clone())))
    }

    pub(super) fn structured_clone(
        &self,
        context: &mut crate::StructuredCloneContext,
    ) -> AuthResult<(Self, T)> {
        let (value, before) = context.clone_record(&self.field_value())?;
        let row = value
            .as_object()
            .and_then(crate::FieldObject::source::<Self>)
            .cloned()
            .ok_or_else(|| AuthError::internal("Structured clone lost its native row type"))?;
        Ok((row, before))
    }
}

impl<T: ObjectRow> crate::store::JoinValue<RowRef<T>> {
    pub(super) fn raw_value(&self) -> FieldValue {
        match self {
            Self::One(row) => row.as_ref().map_or(FieldValue::Null, RowRef::field_value),
            Self::Many(rows) => rows
                .iter()
                .map(RowRef::field_value)
                .collect::<Vec<_>>()
                .into(),
        }
    }
}

impl<T> RowRef<T> {
    pub(super) fn same_row(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.0, &other.0)
    }

    pub(super) fn replace(&self, value: T) -> AuthResult<()> {
        let _operation = self.1.lock();
        let previous = {
            let mut row = lock(&self.0)?;
            std::mem::replace(&mut *row, value)
        };
        drop(previous);
        Ok(())
    }

    pub(super) fn snapshot(&self) -> AuthResult<T>
    where
        T: Clone,
    {
        let _operation = self.1.lock();
        Ok(lock(&self.0)?.clone())
    }
}

fn lock<T>(row: &Mutex<T>) -> AuthResult<MutexGuard<'_, T>> {
    row.lock()
        .map_err(|_| AuthError::internal("Ephemeral row lock poisoned"))
}
pub(super) trait TransactionRow {
    fn transaction_id(&self) -> FieldValue;
}
impl<T: MemoryRow> TransactionRow for T {
    fn transaction_id(&self) -> FieldValue {
        self.id().field_value()
    }
}
impl TransactionRow for FieldMap {
    fn transaction_id(&self) -> FieldValue {
        self.get("id").cloned().unwrap_or_default()
    }
}

pub(super) struct TransactionId(pub(super) FieldValue);

impl PartialEq for TransactionId {
    fn eq(&self, other: &Self) -> bool {
        self.0.same_value_zero(&other.0)
    }
}

impl Eq for TransactionId {}

impl Hash for TransactionId {
    fn hash<H: Hasher>(&self, state: &mut H) {
        match &self.0 {
            FieldValue::Undefined => 0_u8.hash(state),
            FieldValue::Null => 1_u8.hash(state),
            FieldValue::Bool(value) => (2_u8, value).hash(state),
            FieldValue::Number(value) => {
                let bits = if value.is_nan() {
                    f64::NAN.to_bits()
                } else if *value == 0.0 {
                    0
                } else {
                    value.to_bits()
                };
                (3_u8, bits).hash(state);
            }
            FieldValue::String(value) => {
                (4_u8, value.encode_utf16().collect::<Vec<_>>()).hash(state);
            }
            FieldValue::Utf16String(value) => (4_u8, value.as_utf16()).hash(state),
            FieldValue::Date(value) => (5_u8, value.milliseconds().to_bits()).hash(state),
            FieldValue::Array(value) => (6_u8, Arc::as_ptr(value)).hash(state),
            FieldValue::Object(value) => (7_u8, value.identity()).hash(state),
            FieldValue::Function(value) => (8_u8, value.identity()).hash(state),
        }
    }
}
pub(super) fn row_json(row: &impl AuthRecordFields) -> AuthResult<Option<String>> {
    FieldValue::from(row.field_values()?).stringify()
}

macro_rules! row_id {
    ($($record:ty),* $(,)?) => { $(impl MemoryRow for $record {
        fn id(&self) -> &SchemaValue<String> { &self.id }
    })* };
}
row_id!(crate::wire::UserView);

#[cfg(test)]
mod object_tests;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::StructuredCloneContext;
    use crate::store::ephemeral::table::TableRef;
    use std::collections::HashSet;

    #[derive(Clone, Debug, PartialEq)]
    struct Record {
        id: SchemaValue<String>,
        label: String,
    }
    impl MemoryRow for Record {
        fn id(&self) -> &SchemaValue<String> {
            &self.id
        }
    }

    impl AuthRecordFields for Record {
        fn field_values(&self) -> AuthResult<FieldMap> {
            Ok([
                ("id".into(), self.id.field_value()),
                ("label".into(), self.label.clone().into()),
            ]
            .into())
        }
    }
    impl FromFieldMap for Record {
        fn from_field_values(mut fields: FieldMap) -> AuthResult<Self> {
            Ok(Self {
                id: SchemaValue::from_field(fields.remove("id").unwrap_or_default()),
                label: fields.remove("label").unwrap_or_default().decode()?,
            })
        }
    }

    impl ObjectRow for Record {
        fn property(&self, name: &str) -> AuthResult<Option<FieldValue>> {
            Ok(self.field_values()?.get(name).cloned())
        }
    }

    #[test]
    fn transaction_keys_preserve_native_types_and_object_identity() {
        let date = FieldValue::Date(crate::FieldDate::from_milliseconds(1.0));
        let array = FieldValue::from(vec![FieldValue::Number(1.0)]);
        let object = FieldValue::from(FieldMap::new());
        let keys: HashSet<_> = [
            FieldValue::Undefined,
            FieldValue::Null,
            FieldValue::Bool(false),
            FieldValue::Bool(true),
            FieldValue::Number(0.0),
            FieldValue::Number(1.0),
            FieldValue::Number(f64::NAN),
            FieldValue::String("1".into()),
            FieldValue::String("😀".into()),
            FieldValue::Utf16String(crate::Utf16String::from_units(vec![0xd800])),
            date.clone(),
            array.clone(),
            object.clone(),
        ]
        .into_iter()
        .map(TransactionId)
        .collect();
        assert_eq!(keys.len(), 13);
        for equivalent in [
            FieldValue::Number(-0.0),
            FieldValue::Number(f64::from_bits(0x7ff8_0000_0000_0001)),
            FieldValue::Utf16String("😀".into()),
            date,
            array,
            object,
        ] {
            assert!(keys.contains(&TransactionId(equivalent)));
        }
        for distinct in [
            FieldValue::Number(2.0),
            FieldValue::String("0".into()),
            FieldValue::Date(crate::FieldDate::from_milliseconds(1.0)),
            FieldValue::from(vec![FieldValue::Number(1.0)]),
            FieldValue::from(FieldMap::new()),
        ] {
            assert!(!keys.contains(&TransactionId(distinct)));
        }
    }

    #[test]
    fn transaction_numeric_ids_merge_updates_deletes_and_creates_independently() -> AuthResult<()> {
        let mut live = TableRef::new(Arc::default());
        for (id, label) in [
            (FieldValue::Number(1.0), "Alice"),
            (FieldValue::Number(2.0), "Bob"),
            (FieldValue::String("1".into()), "String ID"),
            (FieldValue::Number(3.0), "Deleted"),
        ] {
            let _ = live.push(Record {
                id: SchemaValue::from_field(id),
                label: label.into(),
            })?;
        }
        let base = live.deep_clone(&mut StructuredCloneContext::new())?;
        let mut working = base.deep_clone(&mut StructuredCloneContext::new())?;
        for source in working.snapshot_refs()? {
            let mut row = source.snapshot()?;
            if row.label == "Alice" {
                row.label = "Updated Alice".into();
                source.replace(row)?;
            }
        }
        let deleted = working.select_refs(|row| Ok(row.snapshot()?.label == "Deleted"))?;
        working = working.without_refs(&deleted)?;
        let _ = working.push(Record {
            id: SchemaValue::from_field(FieldValue::Number(4.0)),
            label: "Created".into(),
        })?;
        let bob = live
            .select_refs(|row| Ok(row.snapshot()?.label == "Bob"))?
            .into_iter()
            .next()
            .ok_or_else(|| AuthError::internal("missing Bob fixture"))?;
        let mut updated = bob.snapshot()?;
        updated.label = "Concurrent Bob".into();
        bob.replace(updated)?;
        assert_eq!(
            live.snapshot()?.first().map(|row| row.label.clone()),
            Some("Alice".into())
        );
        assert_eq!(live.len()?, 4);
        live = live.reconcile(&base, &working)?;
        assert_eq!(
            live.snapshot()?
                .iter()
                .map(|row| row.label.as_str())
                .collect::<Vec<_>>(),
            ["Updated Alice", "Concurrent Bob", "String ID", "Created"]
        );
        assert!(live.contains_ref(&bob)?);
        for expected in working.select_refs(|row| {
            Ok(matches!(
                row.snapshot()?.label.as_str(),
                "Updated Alice" | "Created"
            ))
        })? {
            assert!(live.contains_ref(&expected)?);
        }
        Ok(())
    }

    #[test]
    fn transaction_native_duplicate_ids_keep_the_last_row_limitation() -> AuthResult<()> {
        for (first, last) in [
            (Some(FieldValue::Number(1.0)), Some(FieldValue::Number(1.0))),
            (
                Some(FieldValue::Number(f64::NAN)),
                Some(FieldValue::Number(-f64::NAN)),
            ),
            (
                Some(FieldValue::Number(-0.0)),
                Some(FieldValue::Number(0.0)),
            ),
            (None, Some(FieldValue::Undefined)),
        ] {
            let mut live = TableRef::new(Arc::default());
            for (id, label) in [(first, "First"), (last, "Last")] {
                let mut row = FieldMap::from([("label".into(), FieldValue::from(label))]);
                if let Some(id) = id {
                    let _ = row.insert("id".into(), id);
                }
                let _ = live.push(row)?;
            }
            let base = live.deep_clone(&mut StructuredCloneContext::new())?;
            let working = base.deep_clone(&mut StructuredCloneContext::new())?;
            for row in working.snapshot_refs()? {
                if row.field("label")?.as_ref().and_then(FieldValue::as_str) == Some("Last") {
                    let _ = row.set_field("label".into(), "Updated".into())?;
                }
            }
            live = live.reconcile(&base, &working)?;
            assert_eq!(live.len()?, 2);
            for row in live.snapshot()? {
                assert_eq!(
                    row.get("label").and_then(FieldValue::as_str),
                    Some("Updated")
                );
            }
        }
        Ok(())
    }

    #[test]
    fn transaction_public_id_merge_matches_pinned_missing_duplicate_and_changed_ids()
    -> AuthResult<()> {
        for kind in ["undefined", "duplicate", "changed"] {
            let mut live = TableRef::new(Arc::default());
            for (index, label) in ["Alice", "Bob"].into_iter().enumerate() {
                let id = match kind {
                    "undefined" => SchemaValue::Undefined,
                    "duplicate" => SchemaValue::Typed("duplicate".into()),
                    _ => SchemaValue::Typed((index + 1).to_string()),
                };
                let _ = live.push(Record {
                    id,
                    label: label.into(),
                })?;
            }
            let base = live.deep_clone(&mut StructuredCloneContext::new())?;
            let working = base.deep_clone(&mut StructuredCloneContext::new())?;
            {
                let first = working
                    .select_refs(|row| Ok(row.snapshot()?.label == "Alice"))?
                    .into_iter()
                    .next()
                    .ok_or_else(|| AuthError::internal("missing Alice fixture"))?;
                let mut updated = first.snapshot()?;
                if kind == "changed" {
                    updated.id = SchemaValue::Typed("changed-public-id".into());
                }
                updated.label = "Updated Alice".into();
                first.replace(updated)?;
            }
            live = live.reconcile(&base, &working)?;
            let rows = live.snapshot()?;
            let expected = if kind == "changed" {
                ["Bob", "Updated Alice"]
            } else {
                ["Alice", "Bob"]
            };
            assert_eq!(
                rows.iter()
                    .map(|row| row.label.as_str())
                    .collect::<Vec<_>>(),
                expected
            );
            assert_eq!(
                working.snapshot()?.first().map(|row| row.label.clone()),
                Some("Updated Alice".to_owned())
            );
        }
        Ok(())
    }
}
