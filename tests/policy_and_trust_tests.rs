use arkion_identity_proxy::authz::engine::{normalize_path, Decision, PolicyEngine};
use arkion_identity_proxy::authz::model::{AllowRule, IdentityPolicy};
use arkion_identity_proxy::proxy::headers::{
    clean_hop_by_hop_headers, sanitize_and_apply_forwarded_headers, HEADER_PROXY_LOOP,
    HEADER_X_AUTHENTICATED_IDENTITY, HEADER_X_FORWARDED_FOR, HEADER_X_FORWARDED_HOST,
    HEADER_X_FORWARDED_PROTO,
};
use arkion_identity_proxy::tls::load_certs;
use arkion_identity_proxy::trust::DynamicClientCertVerifier;
use http::HeaderMap;
use rustls::server::WebPkiClientVerifier;
use rustls::RootCertStore;
use std::fs;
use std::path::Path;
use std::sync::Arc;

#[test]
fn test_path_normalization() {
    assert_eq!(normalize_path("/payments"), "/payments");
    assert_eq!(normalize_path("/payments/"), "/payments");
    assert_eq!(normalize_path("//payments///123"), "/payments/123");
    assert_eq!(normalize_path("/reports/../payments"), "/payments");
    assert_eq!(normalize_path("/a/b/c/../../d"), "/a/d");
    assert_eq!(normalize_path("/%2D/payments"), "/-/payments");
    assert_eq!(normalize_path("/reports/%2E%2E/payments"), "/payments");
    assert_eq!(normalize_path("/payments?foo=bar#section"), "/payments");
}

#[test]
fn test_policy_engine_evaluation() {
    let policy = IdentityPolicy {
        identity: "spiffe://customer-a/prod/payment-agent".to_string(),
        allow: vec![
            AllowRule {
                method: "POST".to_string(),
                path: "/payments".to_string(),
            },
            AllowRule {
                method: "GET".to_string(),
                path: "/reports/*".to_string(),
            },
        ],
    };

    let engine = PolicyEngine::new(vec![policy]);

    // 1. Allowed exact match
    assert_eq!(
        engine.evaluate(
            "spiffe://customer-a/prod/payment-agent",
            "POST",
            "/payments"
        ),
        Decision::Allow
    );

    // 2. Allowed wildcard match
    assert_eq!(
        engine.evaluate(
            "spiffe://customer-a/prod/payment-agent",
            "GET",
            "/reports/daily/summary"
        ),
        Decision::Allow
    );

    // 3. Wrong method -> Deny
    assert_eq!(
        engine.evaluate("spiffe://customer-a/prod/payment-agent", "PUT", "/payments"),
        Decision::Deny
    );

    // 4. Wrong identity -> Deny
    assert_eq!(
        engine.evaluate("spiffe://customer-b/prod/other", "POST", "/payments"),
        Decision::Deny
    );

    // 5. Path traversal bypass attempt -> Deny
    assert_eq!(
        engine.evaluate(
            "spiffe://customer-a/prod/payment-agent",
            "GET",
            "/reports/../payments"
        ),
        Decision::Deny
    );

    // 6. Ambiguous prefix match -> Deny (/reports vs /reports_secret)
    assert_eq!(
        engine.evaluate(
            "spiffe://customer-a/prod/payment-agent",
            "GET",
            "/reports_secret"
        ),
        Decision::Deny
    );
}

#[test]
fn test_hop_by_hop_header_cleaning() {
    let mut headers = HeaderMap::new();
    headers.insert("connection", "close, x-custom-hop".parse().unwrap());
    headers.insert("keep-alive", "timeout=5".parse().unwrap());
    headers.insert("proxy-authorization", "Basic 123".parse().unwrap());
    headers.insert("x-custom-hop", "temp-val".parse().unwrap());
    headers.insert("content-type", "application/json".parse().unwrap());

    clean_hop_by_hop_headers(&mut headers);

    assert!(!headers.contains_key("connection"));
    assert!(!headers.contains_key("keep-alive"));
    assert!(!headers.contains_key("proxy-authorization"));
    assert!(!headers.contains_key("x-custom-hop"));
    assert_eq!(
        headers.get("content-type").map(|v| v.to_str().unwrap()),
        Some("application/json")
    );
}

#[test]
fn test_forwarded_headers_sanitization() {
    let mut headers = HeaderMap::new();
    headers.insert("x-forwarded-for", "spoofed-client-ip".parse().unwrap());
    headers.insert("forwarded", "for=1.2.3.4".parse().unwrap());

    sanitize_and_apply_forwarded_headers(
        &mut headers,
        "192.168.1.100",
        Some("localhost:8443"),
        "spiffe://customer-a/prod/payment-agent",
    );

    // Spoofed values replaced by trusted proxy values
    assert_eq!(
        headers
            .get(HEADER_X_FORWARDED_FOR)
            .map(|v| v.to_str().unwrap()),
        Some("192.168.1.100")
    );
    assert_eq!(
        headers
            .get(HEADER_X_FORWARDED_HOST)
            .map(|v| v.to_str().unwrap()),
        Some("localhost:8443")
    );
    assert_eq!(
        headers
            .get(HEADER_X_FORWARDED_PROTO)
            .map(|v| v.to_str().unwrap()),
        Some("https")
    );
    assert_eq!(
        headers
            .get(HEADER_X_AUTHENTICATED_IDENTITY)
            .map(|v| v.to_str().unwrap()),
        Some("spiffe://customer-a/prod/payment-agent")
    );
    assert_eq!(
        headers.get(HEADER_PROXY_LOOP).map(|v| v.to_str().unwrap()),
        Some("1")
    );
    assert!(!headers.contains_key("forwarded"));
}

#[test]
fn test_dynamic_trust_store_rotation_logic() {
    let ca_certs = load_certs(Path::new("certs/ca.crt")).expect("Missing ca.crt");
    let mut root_store = RootCertStore::empty();
    for ca in ca_certs {
        root_store.add(ca).unwrap();
    }
    let initial_verifier = WebPkiClientVerifier::builder(Arc::new(root_store))
        .build()
        .unwrap();

    let dynamic_verifier = DynamicClientCertVerifier::new(initial_verifier, 1);
    assert_eq!(dynamic_verifier.root_cert_count(), 1);

    // 1. Valid CA update accepted
    let valid_ca_pem = fs::read("certs/ca.crt").unwrap();
    let result = dynamic_verifier.reload_from_ca_pem(&valid_ca_pem);
    assert!(result.is_ok());
    assert_eq!(dynamic_verifier.root_cert_count(), 1);

    // 2. Invalid CA update rejected -> previous known-good state preserved
    let invalid_pem = b"-----BEGIN CERTIFICATE-----\nINVALID_DATA\n-----END CERTIFICATE-----";
    let bad_result = dynamic_verifier.reload_from_ca_pem(invalid_pem);
    assert!(bad_result.is_err());
    // Known-good root count remains active after bad update!
    assert_eq!(dynamic_verifier.root_cert_count(), 1);
}
