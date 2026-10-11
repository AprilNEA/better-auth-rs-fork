use super::*;

fn organization(suffix: &str, case: Case, function: &FieldValue) -> FieldMap {
    [
        (
            "name".into(),
            if case.function() {
                function.clone()
            } else {
                format!("visible:Organization {suffix}").into()
            },
        ),
        ("slug".into(), format!("slug-{suffix}").into()),
        (
            "logo".into(),
            if suffix == "c" { "other" } else { "linked" }.into(),
        ),
        ("createdAt".into(), date().into()),
        ("metadata".into(), FieldValue::Null),
        ("id".into(), format!("org-{suffix}").into()),
    ]
    .into()
}
fn selected(sqlite: bool, native: bool, case: Case, index: usize) -> Vec<&'static str> {
    if index > 0 || case == Case::FallbackKeyNull && !native {
        Vec::new()
    } else if case.many() {
        vec!["a", "b"]
    } else if case == Case::FallbackKeyRedirect && !native
        || case == Case::UniqueDuplicates && sqlite && native
    {
        vec!["b"]
    } else {
        vec!["a"]
    }
}
fn parent(parent: Parent, case: Case, index: usize, role: &str) -> FieldMap {
    let org: FieldValue = if case.reverse() {
        "org-a".into()
    } else if case == Case::Redirect {
        "slug-b".into()
    } else if case == Case::NullProjection {
        FieldValue::Null
    } else {
        role.into()
    };
    let role: FieldValue = match case {
        Case::FallbackKeyRedirect => "slug-b".into(),
        Case::FallbackKeyNull => FieldValue::Null,
        _ => role.into(),
    };
    let mut row: FieldMap = [("organizationId".into(), org)].into();
    if parent == Parent::Member {
        row.extend([
            ("userId".into(), "user".into()),
            ("role".into(), role),
            ("createdAt".into(), date().into()),
        ]);
    } else {
        row.extend([
            ("email".into(), "owner@list-relations.test".into()),
            ("role".into(), role),
            ("teamId".into(), FieldValue::Null),
            ("status".into(), "pending".into()),
            ("expiresAt".into(), date().into()),
            ("createdAt".into(), date().into()),
            ("inviterId".into(), "user".into()),
        ]);
    }
    let _ = row.insert("id".into(), format!("parent-{index}").into());
    row
}
pub(super) fn result(
    sqlite: bool,
    native: bool,
    kind: Parent,
    case: Case,
    public: bool,
    function: &FieldValue,
) -> FieldValue {
    case.parent_roles()
        .into_iter()
        .enumerate()
        .map(|(index, role)| {
            let selected = selected(sqlite, native, case, index);
            let children = selected
                .iter()
                .map(|suffix| organization(suffix, case, function))
                .collect::<Vec<_>>();
            let relation: FieldValue = if case.many() {
                if public && kind == Parent::Member && case == Case::ManyEmptySchema {
                    children
                        .into_iter()
                        .enumerate()
                        .map(|(index, value)| (index.to_string(), value.into()))
                        .collect::<FieldMap>()
                        .into()
                } else {
                    children
                        .into_iter()
                        .map(FieldValue::from)
                        .collect::<Vec<_>>()
                        .into()
                }
            } else {
                children
                    .first()
                    .cloned()
                    .map(FieldValue::from)
                    .unwrap_or(FieldValue::Null)
            };
            if kind == Parent::Member {
                relation
            } else {
                let mut parent = parent(kind, case, index, role);
                let (name, value) = if public {
                    (
                        "organizationName",
                        match (case.many(), selected.first()) {
                            (false, Some(suffix)) => {
                                if case.function() {
                                    function.clone()
                                } else {
                                    format!("visible:Organization {suffix}").into()
                                }
                            }
                            _ => FieldValue::Undefined,
                        },
                    )
                } else {
                    ("organization", relation)
                };
                let _ = parent.insert(name.into(), value);
                parent.into()
            }
        })
        .collect::<Vec<FieldValue>>()
        .into()
}
pub(super) fn events(sqlite: bool, native: bool, parent: Parent, case: Case) -> Vec<FieldValue> {
    if case.error(parent).is_some() {
        return Vec::new();
    }
    let field = format!(
        "{}.{}",
        parent.model(),
        if case.reverse() {
            "role"
        } else {
            "organizationId"
        }
    );
    let mut events = case
        .parent_roles()
        .into_iter()
        .map(|role| vec![field.clone().into(), role.into()].into())
        .collect::<Vec<_>>();
    if case.fallback_key() {
        events.extend(
            case.parent_roles()
                .into_iter()
                .map(|role| vec![format!("{}.role", parent.model()).into(), role.into()].into()),
        );
    }
    for index in 0..case.parent_roles().len() {
        for child in selected(sqlite, native, case, index) {
            events.push(
                vec![
                    "organization.name".into(),
                    format!("Organization {child}").into(),
                ]
                .into(),
            );
        }
    }
    events
}
