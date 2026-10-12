// The renderer only consumes getColorDepth() !== 1; it does not emit depth-specific escape codes.
pub(super) fn enabled(environment: impl Fn(&str) -> Option<String>) -> bool {
    let nonempty = |name| environment(name).is_some_and(|value| !value.is_empty());
    if let Some(force) = environment("FORCE_COLOR") {
        return matches!(force.as_str(), "" | "1" | "true" | "2" | "3");
    }
    if nonempty("NODE_DISABLE_COLORS")
        || nonempty("NO_COLOR")
        || environment("TERM").as_deref() == Some("dumb")
    {
        return false;
    }
    if nonempty("TMUX")
        || (environment("TF_BUILD").is_some() && environment("AGENT_NAME").is_some())
    {
        return true;
    }
    if environment("CI").is_some() {
        return [
            "APPVEYOR",
            "BUILDKITE",
            "CIRCLECI",
            "DRONE",
            "GITEA_ACTIONS",
            "GITHUB_ACTIONS",
            "GITLAB_CI",
            "TRAVIS",
        ]
        .iter()
        .any(|name| environment(name).is_some())
            || environment("CI_NAME").as_deref() == Some("codeship");
    }
    if let Some(version) = environment("TEAMCITY_VERSION") {
        let Some((major, rest)) = version.split_once('.') else {
            return false;
        };
        return (major.len() >= 2 && major.bytes().all(|byte| byte.is_ascii_digit()))
            || (major == "9"
                && rest.split_once('.').is_some_and(|(minor, _)| {
                    minor.bytes().all(|byte| byte.is_ascii_digit())
                        && minor.bytes().any(|byte| byte != b'0')
                }));
    }
    if matches!(
        environment("TERM_PROGRAM").as_deref(),
        Some("iTerm.app" | "HyperTerm" | "MacTerm" | "Apple_Terminal")
    ) {
        return true;
    }
    if nonempty("COLORTERM") {
        return true;
    }
    let Some(term) = environment("TERM") else {
        return false;
    };
    let term = term.to_lowercase();
    if matches!(
        term.as_str(),
        "eterm"
            | "cons25"
            | "console"
            | "cygwin"
            | "dtterm"
            | "gnome"
            | "hurd"
            | "jfbterm"
            | "konsole"
            | "kterm"
            | "mlterm"
            | "mosh"
            | "putty"
            | "st"
            | "terminator"
            | "constructor"
            | "__proto__"
    ) || ["ansi", "color", "linux", "direct"]
        .iter()
        .any(|value| term.contains(value))
        || ["rxvt", "screen", "xterm", "vt100", "vt220"]
            .iter()
            .any(|value| term.starts_with(value))
    {
        return true;
    }
    term.strip_prefix("con")
        .map(|value| value.trim_start_matches(|character: char| character.is_ascii_digit()))
        .and_then(|value| value.strip_prefix('x'))
        .and_then(|value| value.as_bytes().first())
        .is_some_and(u8::is_ascii_digit)
}

#[cfg(test)]
mod tests {
    use super::enabled;

    #[derive(serde::Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct Case {
        inputs: std::collections::BTreeMap<String, String>,
        expected_colors: bool,
    }

    #[test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "The contract must reject a different color policy for any upstream environment case"
    )]
    fn renderer_matches_upstream_environment_cases() -> Result<(), serde_json::Error> {
        let cases: std::collections::BTreeMap<String, Case> = serde_json::from_str(include_str!(
            "../../../../../tests/fixtures/logger-color-depth-cases-1.7.6.json"
        ))?;
        for (name, case) in cases {
            assert_eq!(
                enabled(|variable| case.inputs.get(variable).cloned()),
                case.expected_colors,
                "{name}"
            );
        }
        Ok(())
    }
}
