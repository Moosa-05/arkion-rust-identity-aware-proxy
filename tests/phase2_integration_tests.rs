use arkion_identity_proxy::authz::engine::PolicyEngine;
use arkion_identity_proxy::authz::model::{AllowRule, IdentityPolicy};
use arkion_identity_proxy::{AppConfig, ProxyServer};
use axum::{
    body::Body,
    extract::Request,
    routing::{get, post},
    Router,
};
use std::fs;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;
use tokio::net::TcpListener;
use tokio::time::sleep;

fn get_free_port() -> u16 {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.local_addr().unwrap().port()
}

/// Mock upstream backend server returning request info
async fn start_mock_upstream(port: u16) {
    let app = Router::new()
        .route(
            "/payments",
            post(|req: Request<Body>| async move {
                let headers = req.headers().clone();
                let fwd_for = headers
                    .get("x-forwarded-for")
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or("")
                    .to_string();
                let auth_id = headers
                    .get("x-authenticated-identity")
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or("")
                    .to_string();
                let has_loop_hdr = headers.contains_key("x-arkion-proxy-loop");

                axum::Json(serde_json::json!({
                    "status": "upstream_ok",
                    "forwarded_for": fwd_for,
                    "authenticated_identity": auth_id,
                    "has_loop_header": has_loop_hdr
                }))
            }),
        )
        .route(
            "/health",
            get(|| async { axum::Json(serde_json::json!({"status": "healthy"})) }),
        );

    let listener = TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], port)))
        .await
        .unwrap();
    axum::serve(listener, app).await.unwrap();
}

#[tokio::test]
async fn test_phase2_full_forwarding_and_authorization() {
    let upstream_port = get_free_port();
    let proxy_port = get_free_port();

    // Start mock upstream backend
    tokio::spawn(async move {
        start_mock_upstream(upstream_port).await;
    });

    sleep(Duration::from_millis(150)).await;

    // Configure Policy Engine
    let policy = IdentityPolicy {
        identity: "spiffe://customer-a/prod/payment-agent".to_string(),
        allow: vec![AllowRule {
            method: "POST".to_string(),
            path: "/payments".to_string(),
        }],
    };
    let engine = PolicyEngine::new(vec![policy]);

    let config = AppConfig {
        proxy_host: "127.0.0.1".to_string(),
        proxy_port,
        upstream_url: format!("http://127.0.0.1:{}", upstream_port),
        server_cert_path: PathBuf::from("certs/server.crt"),
        server_key_path: PathBuf::from("certs/server.key"),
        client_ca_cert_path: PathBuf::from("certs/ca.crt"),
        policy_path: PathBuf::from("config/policy.yaml"),
        max_request_body_bytes: 10 * 1024 * 1024,
        enable_loop_prevention: true,
        upstream_timeout_secs: 10,
        max_concurrent_requests: 1000,
        cb_failure_threshold: 5,
        cb_cooldown_secs: 10,
        dashboard_host: "127.0.0.1".to_string(),
        dashboard_port: 0,
    };

    let server = ProxyServer::new(config).unwrap().with_policy_engine(engine);
    tokio::spawn(async move {
        let _ = server.run().await;
    });

    sleep(Duration::from_millis(250)).await;

    // Setup client with SPIFFE cert
    let ca_pem = fs::read("certs/ca.crt").expect("Missing ca.crt");
    let ca_cert = reqwest::Certificate::from_pem(&ca_pem).expect("Invalid CA cert");

    let mut client_cert_pem =
        fs::read("certs/client_spiffe.crt").expect("Missing client_spiffe.crt");
    let client_key_pem = fs::read("certs/client_spiffe.key").expect("Missing client_spiffe.key");
    client_cert_pem.extend_from_slice(&client_key_pem);

    let identity = reqwest::Identity::from_pem(&client_cert_pem).expect("Invalid client identity");

    let client = reqwest::Client::builder()
        .use_rustls_tls()
        .add_root_certificate(ca_cert)
        .identity(identity)
        .danger_accept_invalid_hostnames(true)
        .build()
        .expect("Failed to build reqwest client");

    // 1. Test ALLOWED request -> forwarded to upstream
    let url_allowed = format!("https://127.0.0.1:{}/payments", proxy_port);
    let resp = client
        .post(&url_allowed)
        .json(&serde_json::json!({"amount": 500}))
        .send()
        .await
        .expect("Allowed request failed");

    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["status"], "upstream_ok");
    assert_eq!(
        body["authenticated_identity"],
        "spiffe://customer-a/prod/payment-agent"
    );
    assert_eq!(body["has_loop_header"], true);

    // 2. Test DENIED request -> 403 Forbidden without reaching upstream
    let url_denied = format!("https://127.0.0.1:{}/reports/secret", proxy_port);
    let resp_denied = client.get(&url_denied).send().await.unwrap();
    assert_eq!(resp_denied.status(), 403);

    // 3. Test Proxy Loop Prevention -> 508 Loop Detected
    let resp_loop = client
        .post(&url_allowed)
        .header("x-arkion-proxy-loop", "1")
        .send()
        .await
        .unwrap();
    assert_eq!(resp_loop.status(), 508);
}

#[tokio::test]
async fn test_phase2_dynamic_trust_rotation_endpoint() {
    let proxy_port = get_free_port();

    let config = AppConfig {
        proxy_host: "127.0.0.1".to_string(),
        proxy_port,
        upstream_url: "http://127.0.0.1:8080".to_string(),
        server_cert_path: PathBuf::from("certs/server.crt"),
        server_key_path: PathBuf::from("certs/server.key"),
        client_ca_cert_path: PathBuf::from("certs/ca.crt"),
        policy_path: PathBuf::from("config/policy.yaml"),
        max_request_body_bytes: 10 * 1024 * 1024,
        enable_loop_prevention: false,
        upstream_timeout_secs: 10,
        max_concurrent_requests: 1000,
        cb_failure_threshold: 5,
        cb_cooldown_secs: 10,
        dashboard_host: "127.0.0.1".to_string(),
        dashboard_port: 0,
    };

    // Policy allowing reload-trust endpoint
    let policy = IdentityPolicy {
        identity: "spiffe://customer-a/prod/payment-agent".to_string(),
        allow: vec![AllowRule {
            method: "POST".to_string(),
            path: "/admin/reload-trust".to_string(),
        }],
    };
    let engine = PolicyEngine::new(vec![policy]);

    let server = ProxyServer::new(config).unwrap().with_policy_engine(engine);
    tokio::spawn(async move {
        let _ = server.run().await;
    });

    sleep(Duration::from_millis(250)).await;

    let ca_pem = fs::read("certs/ca.crt").expect("Missing ca.crt");
    let ca_cert = reqwest::Certificate::from_pem(&ca_pem).expect("Invalid CA cert");

    let mut client_cert_pem =
        fs::read("certs/client_spiffe.crt").expect("Missing client_spiffe.crt");
    let client_key_pem = fs::read("certs/client_spiffe.key").expect("Missing client_spiffe.key");
    client_cert_pem.extend_from_slice(&client_key_pem);

    let identity = reqwest::Identity::from_pem(&client_cert_pem).expect("Invalid client identity");

    let client = reqwest::Client::builder()
        .use_rustls_tls()
        .add_root_certificate(ca_cert)
        .identity(identity)
        .danger_accept_invalid_hostnames(true)
        .build()
        .unwrap();

    let url = format!("https://127.0.0.1:{}/admin/reload-trust", proxy_port);

    // 1. Post valid CA PEM -> returns 200 OK
    let resp = client.post(&url).body(ca_pem).send().await.unwrap();
    assert_eq!(resp.status(), 200);

    // 2. Post invalid CA PEM -> returns 400 Bad Request
    let resp_bad = client
        .post(&url)
        .body("INVALID_PEM_DATA")
        .send()
        .await
        .unwrap();
    assert_eq!(resp_bad.status(), 400);
}
