pub(crate) const MAX_VM_REPEAT_BYTES: usize = 32 * 1024 * 1024;
pub(crate) const MAX_VM_REPEAT_ITEMS: usize = 4_000_000;

/// Repeats `s` while guarding against non-finite counts and excessive allocations.
pub(crate) fn repeat_str_bounded(s: &str, count_val: f64) -> Result<String, String> {
    if !count_val.is_finite() {
        return Err("string repetition count must be finite".into());
    }
    if count_val <= 0.0 || s.is_empty() {
        return Ok(String::new());
    }
    if count_val > MAX_VM_REPEAT_BYTES as f64 {
        return Err(format!(
            "string repetition count exceeds {MAX_VM_REPEAT_BYTES} byte limit"
        ));
    }
    let count = count_val as usize;
    let total = s
        .len()
        .checked_mul(count)
        .ok_or_else(|| "string repetition size overflow".to_string())?;
    if total > MAX_VM_REPEAT_BYTES {
        return Err(format!(
            "string repetition size {total} exceeds {MAX_VM_REPEAT_BYTES} byte limit"
        ));
    }
    Ok(s.repeat(count))
}

/// Repeats `items` while guarding against non-finite counts and excessive list lengths.
pub(crate) fn repeat_list_bounded<T: Clone>(items: &[T], count_val: f64) -> Result<Vec<T>, String> {
    if !count_val.is_finite() {
        return Err("list repetition count must be finite".into());
    }
    if count_val <= 0.0 || items.is_empty() {
        return Ok(Vec::new());
    }
    if count_val > MAX_VM_REPEAT_ITEMS as f64 {
        return Err(format!(
            "list repetition count exceeds {MAX_VM_REPEAT_ITEMS} item limit"
        ));
    }
    let count = count_val as usize;
    let total = items
        .len()
        .checked_mul(count)
        .ok_or_else(|| "list repetition length overflow".to_string())?;
    if total > MAX_VM_REPEAT_ITEMS {
        return Err(format!(
            "list repetition length {total} exceeds {MAX_VM_REPEAT_ITEMS} item limit"
        ));
    }
    let mut out = Vec::with_capacity(total);
    for _ in 0..count {
        out.extend(items.iter().cloned());
    }
    Ok(out)
}

/// Zero-pads `s` to `width_val` while bounding output length.
pub(crate) fn zfill_str_bounded(s: &str, width_val: f64) -> Result<String, String> {
    if !width_val.is_finite() {
        return Err("str.zfill width must be finite".into());
    }
    if width_val <= 0.0 {
        return Ok(s.to_string());
    }
    let max_total = MAX_VM_REPEAT_BYTES;
    if width_val > max_total as f64 {
        return Err(format!("str.zfill width exceeds {max_total} limit"));
    }
    let width = width_val as usize;
    let char_len = s.chars().count();
    if char_len >= width {
        return Ok(s.to_string());
    }
    let pad = width - char_len;
    if s.len().saturating_add(pad) > max_total {
        return Err(format!("str.zfill output exceeds {max_total} byte limit"));
    }
    if let Some(rest) = s.strip_prefix('-') {
        Ok(format!("-{}{rest}", "0".repeat(pad)))
    } else if let Some(rest) = s.strip_prefix('+') {
        Ok(format!("+{}{rest}", "0".repeat(pad)))
    } else {
        Ok(format!("{}{s}", "0".repeat(pad)))
    }
}

/// Returns whether `key` is a security-sensitive process environment variable.
pub(crate) fn is_protected_security_env_var(key: &str) -> bool {
    const PROTECTED: &[&str] = &[
        "KOVREK_CAPS",
        "KOVREK_ACTOR_TOKEN",
        "KOVREK_NOTEBOOK_TOKEN",
        "KOVREK_NOTEBOOK_CAPS",
        "KOVREK_REGISTRY_TOKEN",
        "KOVREK_BIND_HOST",
        "KOVREK_REQUIRE_TOKEN",
        "LD_PRELOAD",
        "LD_LIBRARY_PATH",
        "LD_AUDIT",
        "DYLD_INSERT_LIBRARIES",
        "DYLD_LIBRARY_PATH",
        "DYLD_FRAMEWORK_PATH",
        "NODE_OPTIONS",
        "RUSTC_WRAPPER",
    ];
    PROTECTED.iter().any(|p| key.eq_ignore_ascii_case(p))
}

/// Validates an environment variable key/value pair before mutation.
pub(crate) fn validate_env_assignment(key: &str, value: &str) -> Result<(), String> {
    if key.is_empty() || key.contains(['=', '\0']) || value.contains('\0') {
        return Err("invalid environment variable name or value".into());
    }
    if is_protected_security_env_var(key) {
        return Err(format!(
            "CapabilityError: mutating {key} via env_set is forbidden"
        ));
    }
    Ok(())
}
