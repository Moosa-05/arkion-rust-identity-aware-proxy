use arkion_identity_proxy::authz::engine::PolicyEngine;
use arkion_identity_proxy::authz::model::{AllowRule, IdentityPolicy};
use arkion_identity_proxy::resilience::CircuitBreaker;
use arkion_identity_proxy::{AppConfig, ProxyServer};
use axum::{routing::get, Router};
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

#[tokio::test]
async fn test_circuit_breaker_state_transitions() {
    let cb = CircuitBreaker::new(3, Duration::from_millis(150));

    assert_eq!(cb.state_name(), "CLOSED");
    assert!(cb.check_allow().is_ok());

    // Record 2 failures -> still CLOSED
    cb.record_result(false);
    cb.record_result(false);
    assert_eq!(cb.state_name(), "CLOSED");

    // 3rd failure -> transitions to OPEN
    cb.record_result(false);
    assert_eq!(cb.state_name(), "OPEN");

    // While OPEN -> check_allow fast fails
    assert!(cb.check_allow().is_err());

    // Wait for cooldown (150ms)
    sleep(Duration::from_millis(160)).await;

    // After cooldown -> check_allow transitions to HALF-OPEN for probe
    assert!(cb.check_allow().is_ok());
    assert_eq!(cb.state_name(), "HALF-OPEN");

    // Probe succeeds -> transitions back to CLOSED
    cb.record_result(true);
    assert_eq!(cb.state_name(), "CLOSED");
    assert!(cb.check_allow().is_ok());
}

#[tokio::test]
async fn test_upstream_timeout_504_gateway_timeout() {
    let slow_upstream_port = get_free_port();
    let proxy_port = get_free_port();

    tokio::spawn(async move {
        let app = Router::new().route(
            "/slow",
            get(|| async {
                sleep(Duration::from_secs(1)).await;
                axum::Json(serde_json::json!({"status": "slow_ok"}))
            }),
        );
        let listener = TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], slow_upstream_port)))
            .await
            .unwrap();
        axum::serve(listener, app).await.unwrap();
    });

    sleep(Duration::from_millis(150)).await;

    let policy = IdentityPolicy {
        identity: "spiffe://customer-a/prod/payment-agent".to_string(),
        allow: vec![AllowRule {
            method: "GET".to_string(),
            path: "/slow".to_string(),
        }],
    };
    let engine = PolicyEngine::new(vec![policy]);

    let config = AppConfig {
        proxy_host: "127.0.0.1".to_string(),
        proxy_port,
        upstream_url: format!("http://127.0.0.1:{}", slow_upstream_port),
        server_cert_path: PathBuf::from("certs/server.crt"),
        server_key_path: PathBuf::from("certs/server.key"),
        client_ca_cert_path: PathBuf::from("certs/ca.crt"),
        policy_path: PathBuf::from("config/policy.yaml"),
        max_request_body_bytes: 10 * 1024 * 1024,
        enable_loop_prevention: false,
        upstream_timeout_secs: 1,
        max_concurrent_requests: 100,
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

    let ca_pem = fs::read("certs/ca.crt").unwrap();
    let ca_cert = reqwest::Certificate::from_pem(&ca_pem).unwrap();

    let mut client_cert_pem = fs::read("certs/client_spiffe.crt").unwrap();
    let client_key_pem = fs::read("certs/client_spiffe.key").unwrap();
    client_cert_pem.extend_from_slice(&client_key_pem);

    let identity = reqwest::Identity::from_pem(&client_cert_pem).unwrap();

    let client = reqwest::Client::builder()
        .use_rustls_tls()
        .add_root_certificate(ca_cert)
        .identity(identity)
        .danger_accept_invalid_hostnames(true)
        .timeout(Duration::from_secs(3))
        .build()
        .unwrap();

    let url = format!("https://127.0.0.1:{}/slow", proxy_port);
    let resp = client.get(&url).send().await.unwrap();

    assert!(resp.status() == 200 || resp.status() == 504);
}

#[tokio::test]
async fn test_health_and_readiness_endpoints() {
    let proxy_port = get_free_port();

    let policy = IdentityPolicy {
        identity: "*".to_string(),
        allow: vec![
            AllowRule {
                method: "GET".to_string(),
                path: "/health".to_string(),
            },
            AllowRule {
                method: "GET".to_string(),
                path: "/ready".to_string(),
            },
        ],
    };
    let engine = PolicyEngine::new(vec![policy]);

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
        max_concurrent_requests: 100,
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

    let ca_pem = fs::read("certs/ca.crt").unwrap();
    let ca_cert = reqwest::Certificate::from_pem(&ca_pem).unwrap();

    let mut client_cert_pem = fs::read("certs/client_spiffe.crt").unwrap();
    let client_key_pem = fs::read("certs/client_spiffe.key").unwrap();
    client_cert_pem.extend_from_slice(&client_key_pem);

    let identity = reqwest::Identity::from_pem(&client_cert_pem).unwrap();

    let client = reqwest::Client::builder()
        .use_rustls_tls()
        .add_root_certificate(ca_cert)
        .identity(identity)
        .danger_accept_invalid_hostnames(true)
        .build()
        .unwrap();

    // 1. Health check
    let url_health = format!("https://127.0.0.1:{}/health", proxy_port);
    let resp_health = client.get(&url_health).send().await.unwrap();
    assert_eq!(resp_health.status(), 200);
    let body_health: serde_json::Value = resp_health.json().await.unwrap();
    assert_eq!(body_health["status"], "healthy");

    // 2. Readiness check
    let url_ready = format!("https://127.0.0.1:{}/ready", proxy_port);
    let resp_ready = client.get(&url_ready).send().await.unwrap();
    assert_eq!(resp_ready.status(), 200);
    let body_ready: serde_json::Value = resp_ready.json().await.unwrap();
    assert_eq!(body_ready["status"], "ready");
    assert_eq!(body_ready["circuit_breaker"], "CLOSED");
}

#[tokio::test]
async fn test_local_presentation_http_server() {
    let proxy_port = get_free_port();
    let dash_port = get_free_port();

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
        max_concurrent_requests: 100,
        cb_failure_threshold: 5,
        cb_cooldown_secs: 10,
        dashboard_host: "127.0.0.1".to_string(),
        dashboard_port: dash_port,
    };

    let server = ProxyServer::new(config).unwrap();
    tokio::spawn(async move {
        let _ = server.run().await;
    });

    sleep(Duration::from_millis(250)).await;

    let http_client = reqwest::Client::new();

    // 1. Access dashboard over plain HTTP without client certs
    let dash_url = format!("http://127.0.0.1:{}/dashboard", dash_port);
    let resp = http_client
        .get(&dash_url)
        .send()
        .await
        .expect("Presentation HTTP dashboard failed");
    assert_eq!(resp.status(), 200);
    let html_content = resp.text().await.unwrap();
    assert!(html_content.contains("Arkion Identity-Aware Reverse Proxy"));

    // 2. Access dashboard summary API over plain HTTP
    let summary_url = format!("http://127.0.0.1:{}/api/dashboard-summary", dash_port);
    let resp_summary = http_client
        .get(&summary_url)
        .send()
        .await
        .expect("Presentation summary API failed");
    assert_eq!(resp_summary.status(), 200);
    let body: serde_json::Value = resp_summary.json().await.unwrap();
    assert_eq!(body["proxy_status"], "ONLINE");

    // 3. Confirm unsafe admin endpoint (/admin/reload-trust) is NOT exposed on presentation HTTP server
    let admin_url = format!("http://127.0.0.1:{}/admin/reload-trust", dash_port);
    let resp_admin = http_client
        .post(&admin_url)
        .body("fake-ca")
        .send()
        .await
        .unwrap();
    assert_eq!(resp_admin.status(), 404);
}
