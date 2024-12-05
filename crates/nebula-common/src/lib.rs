pub fn validate_workspace_name(name: &str) -> bool {
    if name.is_empty() || name.len() > 255 || !name.chars().all(|c| c.is_ascii_alphanumeric()) {
        return false;
    }

    true
}
