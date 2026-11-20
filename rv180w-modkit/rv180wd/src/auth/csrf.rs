/// Constant-time comparison for CSRF token validation.
pub fn validate_csrf(expected: &str, provided: Option<&str>) -> bool {
    let Some(provided) = provided else {
        return false;
    };
    if expected.len() != provided.len() {
        return false;
    }
    let mut diff = 0u8;
    for (a, b) in expected.as_bytes().iter().zip(provided.as_bytes().iter()) {
        diff |= a ^ b;
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn csrf_match_and_mismatch() {
        assert!(validate_csrf("tok123", Some("tok123")));
        assert!(!validate_csrf("tok123", Some("tok124")));
        assert!(!validate_csrf("tok123", None));
    }
}
