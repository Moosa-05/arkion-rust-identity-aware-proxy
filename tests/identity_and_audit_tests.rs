use arkion_identity_proxy::audit::AuditEvent;
use arkion_identity_proxy::identity::extractor::{extract_identity_from_der, is_valid_spiffe_uri};
use arkion_identity_proxy::middleware::request_context::extract_or_generate_request_id;
use arkion_identity_proxy::middleware::safe_headers::{extract_safe_headers, is_safe_header};
use http::{HeaderMap, HeaderValue};

#[test]
fn test_spiffe_uri_validation() {
    assert!(is_valid_spiffe_uri(
        "spiffe://customer-a/prod/payment-agent"
    ));
    assert!(is_valid_spiffe_uri("spiffe://domain.com/workload/1"));
    assert!(!is_valid_spiffe_uri("http://customer-a/prod/payment-agent"));
    assert!(!is_valid_spiffe_uri("spiffe://"));
    assert!(!is_valid_spiffe_uri("invalid-uri"));
}

#[test]
fn test_safe_header_filtering() {
    let mut headers = HeaderMap::new();
    headers.insert("host", HeaderValue::from_static("localhost:8443"));
    headers.insert("user-agent", HeaderValue::from_static("curl/7.68.0"));
    headers.insert(
        "authorization",
        HeaderValue::from_static("Bearer secret-token-12345"),
    );
    headers.insert(
        "cookie",
        HeaderValue::from_static("session_id=abcdef123456"),
    );
    headers.insert("x-api-key", HeaderValue::from_static("super-secret-key"));

    let safe_map = extract_safe_headers(&headers);

    // Safe headers MUST be kept
    assert_eq!(
        safe_map.get("host").map(|s| s.as_str()),
        Some("localhost:8443")
    );
    assert_eq!(
        safe_map.get("user-agent").map(|s| s.as_str()),
        Some("curl/7.68.0")
    );

    // Sensitive headers MUST be stripped
    assert!(!safe_map.contains_key("authorization"));
    assert!(!safe_map.contains_key("cookie"));
    assert!(!safe_map.contains_key("x-api-key"));

    assert!(is_safe_header("Host"));
    assert!(!is_safe_header("Authorization"));
    assert!(!is_safe_header("Cookie"));
}

#[test]
fn test_request_id_extraction_and_generation() {
    let mut headers = HeaderMap::new();

    // 1. Missing header -> Generate new UUID v4
    let generated_id = extract_or_generate_request_id(&headers);
    assert!(!generated_id.is_empty());
    assert!(uuid::Uuid::parse_str(&generated_id).is_ok());

    // 2. Valid header present -> Propagate existing
    headers.insert("x-request-id", HeaderValue::from_static("req-custom-12345"));
    let propagated_id = extract_or_generate_request_id(&headers);
    assert_eq!(propagated_id, "req-custom-12345");

    // 3. Invalid / empty header present -> Fallback to new UUID
    headers.insert("x-request-id", HeaderValue::from_static("   "));
    let fallback_id = extract_or_generate_request_id(&headers);
    assert_ne!(fallback_id, "   ");
    assert!(uuid::Uuid::parse_str(&fallback_id).is_ok());
}

#[test]
fn test_audit_event_serialization() {
    let event = AuditEvent::new(
        "9c82-test-id",
        "spiffe://customer-a/prod/payment-agent",
        "POST",
        "/payments",
        "ALLOW",
        Some(200),
        Some(14),
    );

    let json_output = serde_json::to_string(&event).expect("Serialization failed");

    assert!(json_output.contains("\"request_id\":\"9c82-test-id\""));
    assert!(json_output.contains("\"identity\":\"spiffe://customer-a/prod/payment-agent\""));
    assert!(json_output.contains("\"method\":\"POST\""));
    assert!(json_output.contains("\"path\":\"/payments\""));
    assert!(json_output.contains("\"decision\":\"ALLOW\""));
    assert!(json_output.contains("\"upstream_status\":200"));
    assert!(json_output.contains("\"latency_ms\":14"));
}

#[test]
fn test_malformed_der_cert_extraction_handling() {
    let malformed_der = vec![0x00, 0x01, 0x02, 0x03, 0x04];
    let result = extract_identity_from_der(&malformed_der);
    assert!(result.is_err());
}
