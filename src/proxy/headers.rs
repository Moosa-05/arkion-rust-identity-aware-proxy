use http::HeaderMap;

pub const HEADER_PROXY_LOOP: &str = "x-arkion-proxy-loop";
pub const HEADER_X_FORWARDED_FOR: &str = "x-forwarded-for";
pub const HEADER_X_FORWARDED_HOST: &str = "x-forwarded-host";
pub const HEADER_X_FORWARDED_PROTO: &str = "x-forwarded-proto";
pub const HEADER_X_AUTHENTICATED_IDENTITY: &str = "x-authenticated-identity";

pub const HOP_BY_HOP_HEADERS: &[&str] = &[
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
];

/// Sanitizes headers by stripping hop-by-hop headers and any custom headers named in the `Connection` header value.
pub fn clean_hop_by_hop_headers(headers: &mut HeaderMap) {
    let mut custom_hop_headers = Vec::new();

    if let Some(conn) = headers.get(http::header::CONNECTION) {
        if let Ok(conn_str) = conn.to_str() {
            for name in conn_str.split(',') {
                let trimmed = name.trim().to_lowercase();
                if !trimmed.is_empty() {
                    custom_hop_headers.push(trimmed);
                }
            }
        }
    }

    for hop in HOP_BY_HOP_HEADERS {
        headers.remove(*hop);
    }

    for custom in custom_hop_headers {
        headers.remove(custom.as_str());
    }
}

/// Applies proxy-derived forwarding metadata headers while stripping untrusted client-supplied values.
pub fn sanitize_and_apply_forwarded_headers(
    headers: &mut HeaderMap,
    peer_ip: &str,
    host: Option<&str>,
    identity: &str,
) {
    // Strip untrusted client-supplied forwarding headers
    headers.remove("forwarded");
    headers.remove(HEADER_X_FORWARDED_FOR);
    headers.remove(HEADER_X_FORWARDED_HOST);
    headers.remove(HEADER_X_FORWARDED_PROTO);

    // Apply proxy-derived trusted values
    if let Ok(val) = http::HeaderValue::from_str(peer_ip) {
        headers.insert(HEADER_X_FORWARDED_FOR, val);
    }
    if let Some(h) = host {
        if let Ok(val) = http::HeaderValue::from_str(h) {
            headers.insert(HEADER_X_FORWARDED_HOST, val);
        }
    }
    headers.insert(
        HEADER_X_FORWARDED_PROTO,
        http::HeaderValue::from_static("https"),
    );
    if let Ok(val) = http::HeaderValue::from_str(identity) {
        headers.insert(HEADER_X_AUTHENTICATED_IDENTITY, val);
    }

    // Add proxy loop prevention marker
    headers.insert(HEADER_PROXY_LOOP, http::HeaderValue::from_static("1"));
}
