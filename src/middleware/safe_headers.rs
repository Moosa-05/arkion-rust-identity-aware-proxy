use http::HeaderMap;
use std::collections::HashMap;

/// Explicit allowlist of safe header names (lowercase) allowed in audit logs and request contexts.
/// Sensitive headers like `authorization`, `cookie`, `set-cookie`, `x-api-key`, etc. are strictly excluded.
pub const SAFE_HEADER_ALLOWLIST: &[&str] = &[
    "host",
    "user-agent",
    "accept",
    "content-type",
    "content-length",
    "x-request-id",
    "traceparent",
    "tracestate",
    "accept-encoding",
    "accept-language",
];

/// Filters incoming HTTP headers against the safe-header allowlist.
pub fn extract_safe_headers(headers: &HeaderMap) -> HashMap<String, String> {
    let mut safe_map = HashMap::new();

    for (name, value) in headers.iter() {
        let name_str = name.as_str().to_lowercase();
        if SAFE_HEADER_ALLOWLIST.contains(&name_str.as_str()) {
            if let Ok(val_str) = value.to_str() {
                safe_map.insert(name_str, val_str.to_string());
            }
        }
    }

    safe_map
}

/// Helper function to check if a header name is considered safe.
pub fn is_safe_header(header_name: &str) -> bool {
    SAFE_HEADER_ALLOWLIST.contains(&header_name.to_lowercase().as_str())
}
