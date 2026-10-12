use super::{Case, references};
use better_auth_core::{
    AuthError, AuthResult,
    plugin_runtime::ModelFields,
    store::schema::EntityRole,
    user_fields::{UserFieldConfig, UserFieldType},
};
use serde::Deserialize;
use serde_json::{Value, json};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Fixture {
    version: String,
    backend: String,
    groups: Vec<Group>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub(crate) struct Group {
    owner_ref_type: String,
    pub(crate) owner_ref_target: String,
    pub(crate) serial: bool,
    pub(crate) declaration: Value,
    pub(crate) cases: Vec<Case>,
}

impl Group {
    pub(crate) fn field_type(&self) -> AuthResult<UserFieldType> {
        match self.owner_ref_type.as_str() {
            "number" => Ok(UserFieldType::Number),
            "boolean" => Ok(UserFieldType::Boolean),
            "string[]" => Ok(UserFieldType::StringArray),
            "number[]" => Ok(UserFieldType::NumberArray),
            "string" => Ok(UserFieldType::String),
            name => Err(AuthError::internal(format!(
                "Uninventoried Device reference declaration {name}"
            ))),
        }
    }
}

#[expect(
    clippy::panic_in_result_fn,
    reason = "The paired contract must retain the complete replacement declaration and field order"
)]
pub(super) fn assert_declaration(fields: &ModelFields, expected: &Value) -> AuthResult<()> {
    let fields = fields.plugin_fields(EntityRole::DeviceCode);
    let UserFieldConfig {
        field_type,
        required,
        input,
        returned,
        field_name,
        references,
        unique,
        index,
        sortable,
        bigint,
        default_value,
        default_value_fn,
        on_update,
        validator,
        transform,
    } = fields.fields().get("ownerRef").ok_or_else(|| {
        AuthError::internal("The replaced owner reference declaration must exist")
    })?;
    let name = match field_type {
        UserFieldType::Number => "number",
        UserFieldType::Boolean => "boolean",
        UserFieldType::StringArray => "string[]",
        UserFieldType::NumberArray => "number[]",
        UserFieldType::String => "string",
        _ => {
            return Err(AuthError::internal(
                "The retired field type must be replaced",
            ));
        }
    };
    assert!(input.is_none());
    assert!(returned.is_none());
    assert!(unique.is_none());
    assert!(index.is_none());
    assert!(sortable.is_none());
    assert!(bigint.is_none());
    assert!(default_value.is_none());
    assert!(default_value_fn.is_none());
    assert!(on_update.is_none());
    assert!(validator.is_none());
    let reference = references
        .as_ref()
        .ok_or_else(|| AuthError::internal("The replacement must declare its reference target"))?;
    assert!(reference.on_delete.is_none());
    let transform = transform
        .as_ref()
        .ok_or_else(|| AuthError::internal("The replacement must retain both field callbacks"))?;
    assert_eq!(
        &json!({
            "fields": fields.fields().keys().collect::<Vec<_>>(),
            "field": {
                "type": name, "required": required, "fieldName": field_name,
                "references": {"model": reference.model, "field": reference.field},
            },
            "transform": {"input": transform.input.is_some(), "output": transform.output.is_some()},
        }),
        expected,
    );
    Ok(())
}

#[expect(
    clippy::panic_in_result_fn,
    reason = "The paired fixture must retain every declaration, operand, callback, native guard, and storage observation"
)]
pub(crate) fn load_reference_declarations(
    backend: &str,
) -> Result<Vec<Group>, Box<dyn std::error::Error + Send + Sync>> {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(format!(
        "tests/fixtures/device-reference-declarations-{backend}-1.7.6.json"
    ));
    let fixture: Fixture = serde_json::from_slice(&std::fs::read(path)?)?;
    assert_eq!(fixture.version, "1.7.6");
    assert_eq!(fixture.backend, backend);
    assert_eq!(
        fixture
            .groups
            .iter()
            .map(|group| (
                group.owner_ref_type.as_str(),
                group.owner_ref_target.as_str(),
                group.cases.len(),
            ))
            .collect::<Vec<_>>(),
        [
            ("number", "id", 10),
            ("boolean", "id", 5),
            ("string[]", "id", 5),
            ("number[]", "id", 5),
            ("string", "email", 5)
        ],
    );
    for group in &fixture.groups {
        assert_eq!(group.serial, group.owner_ref_target == "id");
        let mut suffixes = vec![
            "logical-equality",
            "physical-membership",
            "mismatch",
            "transaction-commit",
            "transaction-rollback",
        ];
        if group.owner_ref_type == "number" {
            suffixes.extend([
                "id-guard",
                "deviceCode-guard",
                "clientId-guard",
                "userId-guard",
                "status-guard",
            ]);
        }
        for (case, suffix) in group.cases.iter().zip(suffixes) {
            assert_eq!(
                case.name,
                format!(
                    "{}-{}-{suffix}",
                    group.owner_ref_type, group.owner_ref_target
                )
            );
            references::validate_storage(case)?;
            assert_eq!(
                case.seeded.get("ownerRef"),
                Some(&json!(if group.serial {
                    "1"
                } else {
                    "owner@device-where.test"
                }))
            );
            assert_eq!(case.before.len(), 1);
            assert_eq!(
                case.before
                    .first()
                    .and_then(|row| row.get("stored_ownerRef")),
                Some(&if group.serial {
                    json!(1)
                } else {
                    json!("owner@device-where.test")
                })
            );
        }
    }
    Ok(fixture
        .groups
        .into_iter()
        .map(|mut group| {
            group.cases = group
                .cases
                .into_iter()
                .flat_map(|case| {
                    let entry = if case.name.ends_with("physical-membership") {
                        references::Entry::FieldIn
                    } else {
                        references::Entry::FieldEquals
                    };
                    let typed = Case {
                        entry,
                        ..case.clone()
                    };
                    [case, typed]
                })
                .collect();
            group
        })
        .collect())
}
