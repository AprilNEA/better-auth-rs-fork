use crate::{AuthError, AuthResult, FieldValue as Value, WhereMode, WhereOperator};
use std::cmp::Ordering;

pub(crate) fn matches_all<T: Copy>(
    clauses: impl IntoIterator<Item = T>,
    mut evaluate: impl FnMut(T) -> AuthResult<bool>,
) -> AuthResult<bool> {
    let mut clauses = clauses.into_iter();
    let Some(first) = clauses.next() else {
        return Ok(true);
    };
    let mut matched = evaluate(first)?;
    // The Memory adapter evaluates the first clause twice and never short-circuits later clauses.
    for clause in std::iter::once(first).chain(clauses) {
        let clause_matches = evaluate(clause)?;
        matched &= clause_matches;
    }
    Ok(matched)
}

pub(crate) fn matches(
    actual: Option<&Value>,
    expected: &Value,
    operator: WhereOperator,
    mode: WhereMode,
) -> AuthResult<bool> {
    let insensitive = mode == WhereMode::Insensitive
        && (expected.is_string()
            || match expected.as_array() {
                Some(values) => values.every(|value| Ok(value.is_string()))?,
                None => false,
            });
    match operator {
        WhereOperator::Eq if expected.is_null() => {
            Ok(actual.is_none_or(|value| value.is_null() || value.is_undefined()))
        }
        WhereOperator::Eq => Ok(strict_equals(actual, expected, insensitive)),
        WhereOperator::Ne => Ok(!strict_equals(actual, expected, insensitive)),
        WhereOperator::In | WhereOperator::NotIn => {
            let values = expected
                .as_array()
                .ok_or_else(|| AuthError::internal("Value must be an array"))?;
            let mut present = false;
            for value in values.iter()? {
                if includes(actual, &value?, insensitive) {
                    present = true;
                    break;
                }
            }
            Ok(if operator == WhereOperator::In {
                present
            } else {
                !present
            })
        }
        WhereOperator::Lt | WhereOperator::Lte | WhereOperator::Gt | WhereOperator::Gte => {
            if expected.is_null() || expected.is_undefined() {
                return Ok(false);
            }
            let ordering = compare(actual, expected)?;
            Ok(match operator {
                WhereOperator::Lt => ordering == Some(Ordering::Less),
                WhereOperator::Lte => matches!(ordering, Some(Ordering::Less | Ordering::Equal)),
                WhereOperator::Gt => ordering == Some(Ordering::Greater),
                _ => matches!(ordering, Some(Ordering::Greater | Ordering::Equal)),
            })
        }
        WhereOperator::Contains | WhereOperator::StartsWith | WhereOperator::EndsWith => {
            pattern(actual, expected, operator, insensitive)
        }
    }
}

fn strict_equals(actual: Option<&Value>, expected: &Value, insensitive: bool) -> bool {
    if insensitive
        && let Some((actual, expected)) = actual
            .and_then(crate::query::field_string_units)
            .zip(crate::query::field_string_units(expected))
    {
        return lowercase(&actual) == lowercase(&expected);
    }
    actual.unwrap_or(&Value::Undefined).strict_equals(expected)
}

fn includes(actual: Option<&Value>, expected: &Value, insensitive: bool) -> bool {
    if insensitive {
        strict_equals(actual, expected, true)
    } else {
        actual
            .unwrap_or(&Value::Undefined)
            .same_value_zero(expected)
    }
}

fn compare(actual: Option<&Value>, expected: &Value) -> AuthResult<Option<Ordering>> {
    crate::query::field_compare(actual.unwrap_or(&Value::Undefined), expected)
}

fn pattern(
    actual: Option<&Value>,
    expected: &Value,
    operator: WhereOperator,
    insensitive: bool,
) -> AuthResult<bool> {
    if insensitive {
        let Some((actual, expected)) = actual
            .and_then(crate::query::field_string_units)
            .zip(crate::query::field_string_units(expected))
        else {
            return Ok(false);
        };
        return Ok(string_pattern(
            &lowercase(&actual),
            &lowercase(&expected),
            operator,
        ));
    }
    if operator == WhereOperator::Contains {
        match actual {
            None | Some(Value::Undefined | Value::Null) => return Ok(false),
            Some(Value::Array(values)) => {
                return values.includes(expected);
            }
            _ => {}
        }
    }
    if let Some(actual) = actual.and_then(crate::query::field_string_units) {
        return Ok(string_pattern(
            &actual,
            expected.display_utf16()?.as_utf16(),
            operator,
        ));
    }
    let method = match operator {
        WhereOperator::Contains => "includes",
        WhereOperator::StartsWith => "startsWith",
        _ => "endsWith",
    };
    let message = match actual {
        None | Some(Value::Undefined) => {
            format!("undefined is not an object (evaluating 'record[field].{method}')")
        }
        Some(Value::Null) => {
            format!("null is not an object (evaluating 'record[field].{method}')")
        }
        _ => format!("record[field].{method} is not a function"),
    };
    Err(AuthError::internal(message))
}

fn string_pattern(actual: &[u16], expected: &[u16], operator: WhereOperator) -> bool {
    match operator {
        WhereOperator::Contains => {
            expected.is_empty() || actual.windows(expected.len()).any(|part| part == expected)
        }
        WhereOperator::StartsWith => actual.starts_with(expected),
        _ => actual.ends_with(expected),
    }
}

fn lowercase(units: &[u16]) -> Vec<u16> {
    let mut output = Vec::new();
    let mut text = String::new();
    for unit in char::decode_utf16(units.iter().copied()) {
        match unit {
            Ok(character) => text.push(character),
            Err(error) => {
                output.extend(text.to_lowercase().encode_utf16());
                text.clear();
                output.push(error.unpaired_surrogate());
            }
        }
    }
    output.extend(text.to_lowercase().encode_utf16());
    output
}
