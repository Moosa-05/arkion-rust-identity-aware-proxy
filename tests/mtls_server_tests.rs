use arkion_identity_proxy::{AppConfig, ProxyServer};
use axum::{routing::post, Router};
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

async fn start_mock_backend(port: u16) {
    let app = Router::new().route(
        "/payments",
        post(|| async { axum::Json(serde_json::json!({"status": "ok"})) }),
    );
    let listener = TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], port)))
        .await
        .unwrap();
    axum::serve(listener, app).await.unwrap();
}

#[tokio::test]
async fn test_mtls_spiffe_client_authentication() {
    let upstream_port = get_free_port();
    let proxy_port = get_free_port();

    tokio::spawn(async move {
        start_mock_backend(upstream_port).await;
    });

    sleep(Duration::from_millis(150)).await;

    let config = AppConfig {
        proxy_host: "127.0.0.1".to_string(),
        proxy_port,
        upstream_url: format!("http://127.0.0.1:{}", upstream_port),
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

    let server = ProxyServer::new(config).unwrap();
    tokio::spawn(async move {
        let _ = server.run().await;
    });

    sleep(Duration::from_millis(200)).await;

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
        .expect("Failed to build client");

    let url = format!("https://127.0.0.1:{}/payments", proxy_port);
    let resp = client
        .post(&url)
        .header("X-Request-ID", "custom-req-999")
        .header("Authorization", "Bearer sensitive-secret-token")
        .send()
        .await
        .expect("Request failed");

    assert_eq!(resp.status(), 200);

    let resp_req_id = resp
        .headers()
        .get("x-request-id")
        .and_then(|v| v.to_str().ok());
    assert_eq!(resp_req_id, Some("custom-req-999"));
}

#[tokio::test]
async fn test_untrusted_client_rejection() {
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

    let server = ProxyServer::new(config).unwrap();
    tokio::spawn(async move {
        let _ = server.run().await;
    });

    sleep(Duration::from_millis(200)).await;

    let ca_pem = fs::read("certs/ca.crt").expect("Missing ca.crt");
    let ca_cert = reqwest::Certificate::from_pem(&ca_pem).expect("Invalid CA cert");

    let mut client_cert_pem =
        fs::read("certs/untrusted_client.crt").expect("Missing untrusted_client.crt");
    let client_key_pem =
        fs::read("certs/untrusted_client.key").expect("Missing untrusted_client.key");
    client_cert_pem.extend_from_slice(&client_key_pem);

    let untrusted_identity =
        reqwest::Identity::from_pem(&client_cert_pem).expect("Invalid client identity");

    let client = reqwest::Client::builder()
        .use_rustls_tls()
        .add_root_certificate(ca_cert)
        .identity(untrusted_identity)
        .danger_accept_invalid_hostnames(true)
        .build()
        .expect("Failed to build client");

    let url = format!("https://127.0.0.1:{}/payments", proxy_port);
    let result = client.get(&url).send().await;

    assert!(
        result.is_err(),
        "Untrusted client mTLS handshake should have been rejected"
    );
}

#[tokio::test]
async fn test_missing_client_certificate_rejection() {
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

    let server = ProxyServer::new(config).unwrap();
    tokio::spawn(async move {
        let _ = server.run().await;
    });

    sleep(Duration::from_millis(200)).await;

    let ca_pem = fs::read("certs/ca.crt").expect("Missing ca.crt");
    let ca_cert = reqwest::Certificate::from_pem(&ca_pem).expect("Invalid CA cert");

    let client = reqwest::Client::builder()
        .use_rustls_tls()
        .add_root_certificate(ca_cert)
        .danger_accept_invalid_hostnames(true)
        .build()
        .expect("Failed to build client");

    let url = format!("https://127.0.0.1:{}/payments", proxy_port);
    let result = client.get(&url).send().await;

    assert!(
        result.is_err(),
        "Client without certificate should be rejected at TLS layer"
    );
}
