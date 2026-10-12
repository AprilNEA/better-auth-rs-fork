use serde_json::Value as Json;

pub(crate) fn assert_replay(actual: &Json, expected: &Json, path: &str) {
    match (actual, expected) {
        (Json::Object(actual), Json::Object(expected)) => {
            assert_eq!(
                actual.keys().collect::<Vec<_>>(),
                expected.keys().collect::<Vec<_>>(),
                "{path}: own key order"
            );
            for ((name, actual), expected) in actual.iter().zip(expected.values()) {
                let name = name.replace('~', "~0").replace('/', "~1");
                assert_replay(actual, expected, &format!("{path}/{name}"));
            }
        }
        (Json::Array(actual), Json::Array(expected)) => {
            assert_eq!(actual.len(), expected.len(), "{path}: array length");
            for (index, (actual, expected)) in actual.iter().zip(expected).enumerate() {
                assert_replay(actual, expected, &format!("{path}/{index}"));
            }
        }
        _ => assert_eq!(actual, expected, "{path}: complete native value"),
    }
}
