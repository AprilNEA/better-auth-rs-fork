//! Traverse getters before publishing fresh graph identities or filling cyclic references.

#![expect(
    clippy::indexing_slicing,
    reason = "Graph indices originate from the node table; source, node, and value tables retain identical lengths."
)]

use super::{FieldDate, FieldMap, FieldObject, FieldValue, ObjectIdentity};
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
    Array(usize),
    Object(ObjectIdentity),
}

struct CloneEntry {
    _source: FieldValue,
    value: FieldValue,
    original_record: Option<NativeRecord>,
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
        let mut graph = Graph::new(self);
        let edges = fields
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
    Array(Vec<Edge>),
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
            FieldValue::Array(array) => Identity::Array(Arc::as_ptr(array) as *const () as usize),
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
            FieldValue::Array(array) => Node::Array(
                array
                    .iter()
                    .map(|value| self.visit(value))
                    .collect::<AuthResult<_>>()?,
            ),
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
        let mut values: Vec<Option<FieldValue>> = self
            .nodes
            .iter()
            .map(|node| match node {
                Node::Date(date) => Some(date.clone().into()),
                Node::Object { seed, .. } => Some(FieldValue::Object(seed.object.clone())),
                Node::Array(_) | Node::Pending => None,
            })
            .collect();
        for index in 0..self.nodes.len() {
            materialize_array(index, &self.nodes, &mut values)?;
        }
        let values = values
            .into_iter()
            .collect::<Option<Vec<_>>>()
            .ok_or_else(|| {
                AuthError::internal("Structured clone graph contains an unfinished node")
            })?;
        let originals: Vec<_> = self
            .nodes
            .iter()
            .map(|node| match node {
                Node::Object { seed, .. } => seed.original_record.clone(),
                _ => None,
            })
            .collect();
        let mut publish = Vec::new();
        for node in self.nodes {
            if let Node::Object {
                seed,
                fields,
                state,
            } = node
            {
                let fields = fields
                    .into_iter()
                    .map(|(name, edge)| (name, edge.resolve(&values)))
                    .collect();
                let state = state.iter().map(|edge| edge.resolve(&values)).collect();
                publish.push((seed.prepare)(fields, state)?);
            }
        }
        let copies = self
            .sources
            .into_iter()
            .zip(values.iter().cloned())
            .zip(originals)
            .map(|(((identity, source), value), original_record)| {
                (
                    identity,
                    CloneEntry {
                        _source: source,
                        value,
                        original_record,
                    },
                )
            })
            .collect();
        Ok((values, copies, publish))
    }
}

fn materialize_array(
    index: usize,
    nodes: &[Node],
    values: &mut [Option<FieldValue>],
) -> AuthResult<FieldValue> {
    if let Some(value) = &values[index] {
        return Ok(value.clone());
    }
    let Node::Array(edges) = &nodes[index] else {
        return Err(AuthError::internal(
            "Structured clone graph contains an unfinished node",
        ));
    };
    // Immutable arrays cannot form a cycle without an object, whose placeholder already exists.
    let array = edges
        .iter()
        .map(|edge| match edge {
            Edge::Value(value) => Ok(value.clone()),
            Edge::Node(index) => materialize_array(*index, nodes, values),
        })
        .collect::<AuthResult<Vec<_>>>()?;
    let value = FieldValue::from(array);
    values[index] = Some(value.clone());
    Ok(value)
}

#[cfg(test)]
#[path = "structured_clone_tests.rs"]
mod tests;
