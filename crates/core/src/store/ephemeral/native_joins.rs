//! Native Memory joins group all parents before pagination and retain live child rows.

use super::rows::{ObjectRow, RecordSource, RowRef};
use super::table::TableRef;
use crate::store::{JoinValue, ResolvedJoin, schema::EntityRole};
use crate::{AuthResult, FieldMap, FieldValue};

pub(super) struct NativeRelationship<T> {
    pub(super) parent: FieldMap,
    pub(super) children: Vec<Vec<RowRef<T>>>,
    ids: Vec<Vec<FieldValue>>,
}

pub(super) fn raw_relation<T: ObjectRow + Clone + Send + 'static>(
    rows: &[RowRef<T>],
    many: bool,
) -> FieldValue {
    if many {
        JoinValue::Many(rows.to_vec()).raw_value()
    } else {
        JoinValue::One(rows.first().cloned()).raw_value()
    }
}

pub(super) fn native_relationships<T: ObjectRow + Clone>(
    parents: Vec<RecordSource>,
    relations: &[(EntityRole, &ResolvedJoin, f64)],
    mut capture_table: impl FnMut(EntityRole) -> AuthResult<TableRef<T>>,
) -> AuthResult<Vec<NativeRelationship<T>>> {
    let mut groups = indexmap::IndexMap::new();
    for parent in parents {
        let id = parent.field("id")?.unwrap_or_default().display_utf16()?;
        let group = match groups.entry(id.as_utf16().to_vec()) {
            indexmap::map::Entry::Occupied(entry) => entry.into_mut(),
            indexmap::map::Entry::Vacant(entry) => entry.insert(NativeRelationship {
                parent: parent.shallow_fields()?,
                children: vec![Vec::new(); relations.len()],
                ids: vec![Vec::new(); relations.len()],
            }),
        };
        for (((role, relation, limit), selected), ids) in relations
            .iter()
            .zip(&mut group.children)
            .zip(&mut group.ids)
        {
            let matches = capture_table(*role)?.select_refs(|row| {
                Ok(row
                    .field(&relation.to)?
                    .unwrap_or_default()
                    .strict_equals(&parent.field(&relation.from)?.unwrap_or_default()))
            })?;
            if !relation.many {
                *selected = matches.into_iter().take(1).collect();
                continue;
            }
            let mut added = 0_usize;
            for child in matches {
                if added as f64 >= *limit {
                    break;
                }
                let id = child.field("id")?.unwrap_or_default();
                if !ids.iter().any(|seen| seen.same_value_zero(&id)) {
                    ids.push(id);
                    selected.push(child);
                    added += 1;
                }
            }
        }
    }
    Ok(groups.into_values().collect())
}
