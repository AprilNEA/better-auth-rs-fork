//! Traverse getters before publishing fresh graph identities or filling cyclic references.

#![expect(
    clippy::indexing_slicing,
    reason = "Graph indices originate from the node table; source, node, and value tables retain identical lengths."
)]

use super::{
    ArrayIdentity, FieldArray, FieldDate, FieldMap, FieldObject, FieldValue, ObjectIdentity,
};
use crate::{AuthError, AuthResult};
use std::any::Any;
use std::collections::HashMap;
use std::sync::Arc;

#[expect(
    clippy::expect_used,
    reason = "Clone targets remain private until publication; no callback can lock or poison a fresh target."
)]
pub(crate) fn publish_clone<T>(target: &std::sync::Mutex<T>, value: T) {
    let previous = {
        let mut target = target
            .lock()
            .expect("A private clone target cannot be poisoned");
        std::mem::replace(&mut *target, value)
    };
    drop(previous);
}

type Publish = Box<dyn FnOnce() + Send + Sync>;
type Prepare = Box<dyn FnOnce(FieldMap, Vec<FieldValue>) -> AuthResult<Publish>>;
type PrepareArray = Box<dyn FnOnce(usize, Vec<(usize, FieldValue)>) -> AuthResult<Publish>>;

pub(crate) struct ArrayCloneSeed {
    pub(crate) array: FieldArray,
    pub(crate) prepare: PrepareArray,
}

type NativeRecord = Arc<dyn Any + Send + Sync>;

/// A fresh object retains its native record shape until every graph conversion succeeds.
pub(crate) struct ObjectCloneSeed {
    pub(crate) object: FieldObject,
    pub(crate) state: Vec<FieldValue>,
    pub(crate) original_record: Option<NativeRecord>,
    pub(crate) prepare: Prepare,
}

#[derive(Clone, Copy, Hash, PartialEq, Eq)]
enum Identity {
    Date(usize),
    Array(ArrayIdentity),
    Object(ObjectIdentity),
}

struct CloneEntry {
    _source: FieldValue,
    value: FieldValue,
    original_record: Option<NativeRecord>,
    original_elements: Option<Vec<FieldValue>>,
}

type Copies = Vec<(Identity, CloneEntry)>;

/// Copy one value graph with fresh object identities and preserved aliases.
/// Reuse one context across all records in a transaction snapshot.
/// Create a new context for each independent snapshot.
#[derive(Default)]
pub struct StructuredCloneContext {
    // Source handles prevent pointer reuse between calls through the same context.
    copies: HashMap<Identity, CloneEntry>,
    pending: Option<Vec<Publish>>,
}

impl StructuredCloneContext {
    pub fn new() -> Self {
        Self::default()
    }

    pub(crate) fn deferred() -> Self {
        Self {
            copies: HashMap::new(),
            pending: Some(Vec::new()),
        }
    }

    pub(crate) fn publish(mut self) {
        // Prepared writes contain no getters or fallible conversions, so publication cannot leave half-filled cycles.
        if let Some(pending) = self.pending.take() {
            for apply in pending {
                apply();
            }
        }
    }

    fn complete(&mut self, copies: Copies, publish: Vec<Publish>) {
        if let Some(pending) = &mut self.pending {
            pending.extend(publish);
        } else {
            for apply in publish {
                apply();
            }
        }
        self.copies.extend(copies);
    }

    /// Copy a value while preserving aliases already copied by this context.
    pub fn clone_value(&mut self, value: &FieldValue) -> AuthResult<FieldValue> {
        let mut graph = Graph::new(self);
        let edge = graph.visit(value)?;
        let (values, copies, publish) = graph.materialize()?;
        let value = edge.resolve(&values);
        self.complete(copies, publish);
        Ok(value)
    }

    /// Copy record fields using the same alias map as other records in this context.
    pub fn clone_map(&mut self, fields: &FieldMap) -> AuthResult<FieldMap> {
        let mut ordered = fields.clone();
        ordered.sort_property_order();
        let mut graph = Graph::new(self);
        let edges = ordered
            .iter()
            .map(|(name, value)| Ok((name.clone(), graph.visit(value)?)))
            .collect::<AuthResult<Vec<_>>>()?;
        let (values, copies, publish) = graph.materialize()?;
        let fields = edges
            .into_iter()
            .map(|(name, edge)| (name, edge.resolve(&values)))
            .collect();
        self.complete(copies, publish);
        Ok(fields)
    }

    /// Clone one native schema field using the same object graph as its containing record.
    pub fn clone_field<T: crate::SchemaField>(&mut self, value: &T) -> AuthResult<T> {
        self.clone_value(&value.clone().into_field())?.decode()
    }

    pub(crate) fn clone_array(
        &mut self,
        array: &FieldArray,
    ) -> AuthResult<(FieldArray, Vec<FieldValue>)> {
        let value = self.clone_value(&FieldValue::Array(array.clone()))?;
        let original = self
            .copies
            .get(&Identity::Array(array.identity()))
            .and_then(|copy| copy.original_elements.clone())
            .ok_or_else(|| {
                AuthError::internal("Structured clone lost its original array elements")
            })?;
        let FieldValue::Array(copied) = value else {
            return Err(AuthError::internal("Structured clone lost its array type"));
        };
        Ok((copied, original))
    }

    pub(crate) fn clone_record<T: Clone + 'static>(
        &mut self,
        value: &FieldValue,
    ) -> AuthResult<(FieldValue, T)> {
        let copied = self.clone_value(value)?;
        let original = value
            .as_object()
            .and_then(|source| self.copies.get(&Identity::Object(source.identity())))
            .and_then(|copy| copy.original_record.as_deref())
            .and_then(|record| record.downcast_ref::<T>())
            .ok_or_else(|| AuthError::internal("Structured clone lost its original native row"))?;
        Ok((copied, original.clone()))
    }
}

enum Edge {
    Value(FieldValue),
    Node(usize),
}

impl Edge {
    fn resolve(&self, values: &[FieldValue]) -> FieldValue {
        match self {
            Self::Value(value) => value.clone(),
            Self::Node(index) => values[*index].clone(),
        }
    }
}

enum Node {
    Pending,
    Date(FieldDate),
    Array {
        seed: ArrayCloneSeed,
        length: usize,
        entries: Vec<(usize, FieldValue, Edge)>,
    },
    Object {
        seed: ObjectCloneSeed,
        fields: Vec<(String, Edge)>,
        state: Vec<Edge>,
    },
}

struct Graph<'a> {
    context: &'a StructuredCloneContext,
    indices: HashMap<Identity, usize>,
    sources: Vec<(Identity, FieldValue)>,
    nodes: Vec<Node>,
}

impl<'a> Graph<'a> {
    fn new(context: &'a StructuredCloneContext) -> Self {
        Self {
            context,
            indices: HashMap::new(),
            sources: Vec::new(),
            nodes: Vec::new(),
        }
    }

    fn visit(&mut self, value: &FieldValue) -> AuthResult<Edge> {
        let identity = match value {
            FieldValue::Function(_) => return Err(AuthError::DataClone),
            FieldValue::Date(date) => Identity::Date(Arc::as_ptr(&date.0) as usize),
            FieldValue::Array(array) => Identity::Array(array.identity()),
            FieldValue::Object(object) => Identity::Object(object.identity()),
            value => return Ok(Edge::Value(value.clone())),
        };
        if let Some(copy) = self.context.copies.get(&identity) {
            return Ok(Edge::Value(copy.value.clone()));
        }
        if let Some(index) = self.indices.get(&identity) {
            return Ok(Edge::Node(*index));
        }
        let index = self.nodes.len();
        let _ = self.indices.insert(identity, index);
        self.sources.push((identity, value.clone()));
        self.nodes.push(Node::Pending);
        let node = match value {
            FieldValue::Date(date) => Node::Date(FieldDate(Arc::new(*date.0))),
            FieldValue::Array(array) => {
                let seed = array.clone_seed()?;
                let length = array.len()?;
                let mut entries = Vec::new();
                for index in array.own_indices()? {
                    if let Some(value) = array.get(index)? {
                        let edge = self.visit(&value)?;
                        entries.push((index, value, edge));
                    }
                }
                Node::Array {
                    seed,
                    length,
                    entries,
                }
            }
            FieldValue::Object(object) => {
                let mut seed = object.clone_seed()?;
                let mut fields = Vec::new();
                for name in object.own_keys()? {
                    if let Some(value) = object.get(&name)? {
                        fields.push((name, self.visit(&value)?));
                    }
                }
                let state = std::mem::take(&mut seed.state)
                    .iter()
                    .map(|value| self.visit(value))
                    .collect::<AuthResult<_>>()?;
                Node::Object {
                    seed,
                    fields,
                    state,
                }
            }
            _ => {
                return Err(AuthError::internal(
                    "Structured clone graph contains a non-object node",
                ));
            }
        };
        self.nodes[index] = node;
        Ok(Edge::Node(index))
    }

    fn materialize(self) -> AuthResult<(Vec<FieldValue>, Copies, Vec<Publish>)> {
        let values = self
            .nodes
            .iter()
            .map(|node| match node {
                Node::Date(date) => Some(date.clone().into()),
                Node::Object { seed, .. } => Some(FieldValue::Object(seed.object.clone())),
                Node::Array { seed, .. } => Some(FieldValue::Array(seed.array.clone())),
                Node::Pending => None,
            })
            .collect::<Option<Vec<_>>>()
            .ok_or_else(|| {
                AuthError::internal("Structured clone graph contains an unfinished node")
            })?;
        let originals = self
            .nodes
            .iter()
            .map(|node| match node {
                Node::Object { seed, .. } => (seed.original_record.clone(), None),
                Node::Array { entries, .. } => (
                    None,
                    Some(entries.iter().map(|(_, value, _)| value.clone()).collect()),
                ),
                _ => (None, None),
            })
            .collect::<Vec<_>>();
        let mut publish = Vec::new();
        for node in self.nodes {
            match node {
                Node::Object {
                    seed,
                    fields,
                    state,
                } => {
                    let fields = fields
                        .into_iter()
                        .map(|(name, edge)| (name, edge.resolve(&values)))
                        .collect();
                    let state = state.iter().map(|edge| edge.resolve(&values)).collect();
                    publish.push((seed.prepare)(fields, state)?);
                }
                Node::Array {
                    seed,
                    length,
                    entries,
                } => {
                    let entries = entries
                        .into_iter()
                        .map(|(index, _, edge)| (index, edge.resolve(&values)))
                        .collect();
                    publish.push((seed.prepare)(length, entries)?);
                }
                _ => {}
            }
        }
        let copies = self
            .sources
            .into_iter()
            .zip(values.iter().cloned())
            .zip(originals)
            .map(
                |(((identity, source), value), (original_record, original_elements))| {
                    (
                        identity,
                        CloneEntry {
                            _source: source,
                            value,
                            original_record,
                            original_elements,
                        },
                    )
                },
            )
            .collect();
        Ok((values, copies, publish))
    }
}

#[cfg(test)]
#[path = "structured_clone_tests.rs"]
mod tests;
