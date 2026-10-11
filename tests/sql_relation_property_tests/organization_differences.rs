use super::{AuthError, TestResult, Value, json};

struct Difference {
    scenario: &'static str,
    upstream_message: &'static str,
    rust_message: &'static str,
    reason: &'static str,
    sqlite: bool,
}

const DIFFERENCES: [Difference; 7] = [
    Difference {
        scenario: "preceding-relations",
        upstream_message: "datatype mismatch",
        rust_message: "Binding expected string, TypedArray, boolean, number, bigint or null",
        reason: "Bun SQLite rejects the projected relation page with SQLITE_MISMATCH. The Rust shared binder rejects its object parameter before execution.",
        sqlite: true,
    },
    Difference {
        scenario: "mapped-preceding-relations",
        upstream_message: "datatype mismatch",
        rust_message: "Binding expected string, TypedArray, boolean, number, bigint or null",
        reason: "A mapped preceding relationship reaches the same unresolved Bun parameter overload boundary.",
        sqlite: true,
    },
    Difference {
        scenario: "member-singular-present",
        upstream_message: "members.map is not a function. (In 'members.map((member) => member.userId)', 'members.map' is undefined)",
        rust_message: "members.map is not a function",
        reason: "Bun includes its evaluated JavaScript expression. JoinValue uses the shared engine-independent message.",
        sqlite: false,
    },
    Difference {
        scenario: "member-singular-empty",
        upstream_message: "null is not an object (evaluating 'members.map')",
        rust_message: "Cannot read properties of null (reading 'map')",
        reason: "Bun names the null receiver expression. JoinValue uses the existing V8-style null-property message.",
        sqlite: false,
    },
    Difference {
        scenario: "invitation-singular-present",
        upstream_message: "invitations.map is not a function. (In 'invitations.map((inv) => filterOutputFields(inv, invitationAdditionalFields))', 'invitations.map' is undefined)",
        rust_message: "invitations.map is not a function",
        reason: "Bun includes the invitation filtering expression. The shared public consumer retains the JoinValue message.",
        sqlite: false,
    },
    Difference {
        scenario: "invitation-singular-empty",
        upstream_message: "null is not an object (evaluating 'invitations.map')",
        rust_message: "Cannot read properties of null (reading 'map')",
        reason: "Bun names the invitation receiver expression. JoinValue uses the existing V8-style null-property message.",
        sqlite: false,
    },
    Difference {
        scenario: "team-singular-present",
        upstream_message: "teams?.map is not a function. (In 'teams?.map((team) => filterOutputFields(team, teamAdditionalFields))', 'teams?.map' is undefined)",
        rust_message: "teams?.map is not a function",
        reason: "Bun includes the optional team filtering expression. The shared public consumer has a shorter TypeError message.",
        sqlite: false,
    },
];

pub(super) fn assert_error(scenario: &str, expected: &Value, error: &AuthError) -> TestResult {
    if let Some(difference) = DIFFERENCES.iter().find(|entry| entry.scenario == scenario) {
        let (name, properties, keys) = if difference.sqlite {
            (
                "SQLiteError",
                json!({"code":"SQLITE_MISMATCH", "errno":20, "byteOffset":-1}),
                json!(["code", "errno", "byteOffset"]),
            )
        } else {
            ("TypeError", json!({}), json!([]))
        };
        assert_eq!(
            expected,
            &json!({
                "name": name,
                "message": difference.upstream_message,
                "sameCallbackError": false,
                "properties": properties,
                "keys": keys,
            }),
            "{scenario}: {}",
            difference.reason
        );
        assert_eq!(
            error.instrumentation_message(),
            difference.rust_message,
            "{scenario}: {}",
            difference.reason
        );
        assert!(
            if difference.sqlite {
                matches!(error, AuthError::Internal(_))
            } else {
                matches!(error, AuthError::TypeError(_))
            },
            "{scenario}: {}: {error:?}",
            difference.reason
        );
        return Ok(());
    }
    assert_eq!(
        Some(error.instrumentation_message().as_str()),
        expected.get("message").and_then(Value::as_str),
        "{scenario}"
    );
    match expected.get("name").and_then(Value::as_str) {
        Some("TypeError") => assert!(
            matches!(error, AuthError::TypeError(_)),
            "{scenario}: {error:?}"
        ),
        Some("BetterAuthError") => assert!(
            matches!(error, AuthError::Internal(_) | AuthError::Config(_)),
            "{scenario}: {error:?}"
        ),
        name => return Err(format!("Unclassified upstream error: {name:?}").into()),
    }
    Ok(())
}
