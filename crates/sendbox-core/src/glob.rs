#[must_use]
pub fn glob_matches(value: &str, pattern: &str) -> bool {
    if pattern == "*" {
        return true;
    }
    let value = value.chars().collect::<Vec<_>>();
    let pattern = pattern.chars().collect::<Vec<_>>();
    let (mut value_index, mut pattern_index) = (0usize, 0usize);
    let (mut star_value_index, mut star_pattern_index) = (None, None);

    while value_index < value.len() {
        if pattern_index < pattern.len()
            && (pattern[pattern_index] == '?' || pattern[pattern_index] == value[value_index])
        {
            value_index += 1;
            pattern_index += 1;
        } else if pattern_index < pattern.len() && pattern[pattern_index] == '*' {
            star_pattern_index = Some(pattern_index);
            star_value_index = Some(value_index);
            pattern_index += 1;
        } else if let (Some(star_pattern), Some(star_value)) =
            (star_pattern_index, star_value_index)
        {
            pattern_index = star_pattern + 1;
            let next_value = star_value + 1;
            star_value_index = Some(next_value);
            value_index = next_value;
        } else {
            return false;
        }
    }
    while pattern_index < pattern.len() && pattern[pattern_index] == '*' {
        pattern_index += 1;
    }
    pattern_index == pattern.len()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preserves_swift_character_glob_semantics() {
        assert!(glob_matches("filesystem.read", "filesystem.*"));
        assert!(glob_matches("abc", "a?c"));
        assert!(!glob_matches("abc", "a?d"));
        assert!(glob_matches("😀x", "?x"));
        assert!(glob_matches("", "*"));
        assert!(!glob_matches("", "?"));
        assert!(glob_matches("ab", "**a**b**"));
    }
}
