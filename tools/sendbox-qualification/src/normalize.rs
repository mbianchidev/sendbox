use serde_json::Value;

use crate::model::Replacement;

#[must_use]
pub fn normalize_output(
    input: &[u8],
    replacements: &[Replacement],
    redact_json_keys: &[String],
) -> String {
    let mut text = String::from_utf8_lossy(input).replace("\r\n", "\n");
    for replacement in replacements {
        text = text.replace(&replacement.find, &replacement.replace);
    }
    let trimmed = text.trim_end();
    match serde_json::from_str::<Value>(trimmed) {
        Ok(mut value) => {
            redact(&mut value, redact_json_keys);
            serde_json::to_string(&value).expect("JSON values serialize")
        }
        Err(_) => trimmed.to_owned(),
    }
}

fn redact(value: &mut Value, keys: &[String]) {
    match value {
        Value::Object(object) => {
            for (key, nested) in object {
                if keys.iter().any(|candidate| candidate == key) {
                    *nested = Value::String("<normalized>".to_owned());
                } else {
                    redact(nested, keys);
                }
            }
        }
        Value::Array(values) => {
            for nested in values {
                redact(nested, keys);
            }
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes_lines_replacements_and_json_keys() {
        let normalized = normalize_output(
            br#"{"path":"/tmp/a","nested":{"timestamp":"now"}}
"#,
            &[Replacement {
                find: "/tmp/a".to_owned(),
                replace: "<path>".to_owned(),
            }],
            &["timestamp".to_owned()],
        );
        assert_eq!(
            normalized,
            r#"{"nested":{"timestamp":"<normalized>"},"path":"<path>"}"#
        );
    }
}
