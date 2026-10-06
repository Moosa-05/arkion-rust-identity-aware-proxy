use arkion_identity_proxy::authz::engine::PolicyEngine;
use arkion_identity_proxy::authz::model::{AllowRule, IdentityPolicy};
use arkion_identity_proxy::{AppConfig, ProxyServer};
use axum::{routing::post, Router};
use std::fs;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};
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

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("==================================================");
    println!("ARKION IDENTITY-AWARE PROXY — PERFORMANCE BENCHMARK");
    println!("==================================================");

    let upstream_port = get_free_port();
    let proxy_port = get_free_port();

    tokio::spawn(async move {
        start_mock_backend(upstream_port).await;
    });

    sleep(Duration::from_millis(150)).await;

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
        enable_loop_prevention: false,
        upstream_timeout_secs: 10,
        max_concurrent_requests: 5000,
        cb_failure_threshold: 100,
        cb_cooldown_secs: 10,
        dashboard_host: "127.0.0.1".to_string(),
        dashboard_port: 0,
    };

    let server = ProxyServer::new(config)?.with_policy_engine(engine);
    tokio::spawn(async move {
        let _ = server.run().await;
    });

    sleep(Duration::from_millis(250)).await;

    // Load CA & Client mTLS certs
    let ca_pem = fs::read("certs/ca.crt")?;
    let ca_cert = reqwest::Certificate::from_pem(&ca_pem)?;

    let mut client_cert_pem = fs::read("certs/client_spiffe.crt")?;
    let client_key_pem = fs::read("certs/client_spiffe.key")?;
    client_cert_pem.extend_from_slice(&client_key_pem);

    let identity = reqwest::Identity::from_pem(&client_cert_pem)?;

    let proxy_client = reqwest::Client::builder()
        .use_rustls_tls()
        .add_root_certificate(ca_cert)
        .identity(identity)
        .danger_accept_invalid_hostnames(true)
        .pool_max_idle_per_host(50)
        .build()?;

    let direct_client = reqwest::Client::builder()
        .pool_max_idle_per_host(50)
        .build()?;

    let total_requests = 300;
    let concurrency = 10;

    println!("\nRunning Baseline Benchmark (Direct HTTP to Upstream)...");
    let direct_url = format!("http://127.0.0.1:{}/payments", upstream_port);
    let direct_results =
        run_benchmark_suite(direct_client, &direct_url, total_requests, concurrency).await;

    println!("\nRunning Proxy Benchmark (mTLS -> Intercept -> Authz -> Upstream)...");
    let proxy_url = format!("https://127.0.0.1:{}/payments", proxy_port);
    let proxy_results =
        run_benchmark_suite(proxy_client, &proxy_url, total_requests, concurrency).await;

    let overhead_ms = (proxy_results.p50_ms - direct_results.p50_ms).max(0.0);

    println!("\n==================================================");
    println!("BENCHMARK SUMMARY RESULTS");
    println!("==================================================");
    println!("Metric                  | Direct Upstream | Rust mTLS Proxy");
    println!("------------------------|-----------------|-----------------");
    println!(
        "Requests / Sec (RPS)    | {:<15.2} | {:<15.2}",
        direct_results.rps, proxy_results.rps
    );
    println!(
        "p50 Latency (ms)        | {:<15.2} | {:<15.2}",
        direct_results.p50_ms, proxy_results.p50_ms
    );
    println!(
        "p95 Latency (ms)        | {:<15.2} | {:<15.2}",
        direct_results.p95_ms, proxy_results.p95_ms
    );
    println!(
        "p99 Latency (ms)        | {:<15.2} | {:<15.2}",
        direct_results.p99_ms, proxy_results.p99_ms
    );
    println!(
        "Error Rate (%)          | {:<15.2} | {:<15.2}",
        direct_results.error_rate, proxy_results.error_rate
    );
    println!("--------------------------------------------------");
    println!("Measured Proxy Overhead (p50): ~{:.2} ms", overhead_ms);
    println!("==================================================");

    Ok(())
}

struct BenchResults {
    rps: f64,
    p50_ms: f64,
    p95_ms: f64,
    p99_ms: f64,
    error_rate: f64,
}

async fn run_benchmark_suite(
    client: reqwest::Client,
    url: &str,
    total_requests: usize,
    concurrency: usize,
) -> BenchResults {
    let client = Arc::new(client);
    let url = Arc::new(url.to_string());
    let requests_per_task = total_requests / concurrency;

    let start_time = Instant::now();
    let mut handles = Vec::new();

    for _ in 0..concurrency {
        let client_clone = client.clone();
        let url_clone = url.clone();
        let handle = tokio::spawn(async move {
            let mut latencies = Vec::with_capacity(requests_per_task);
            let mut errors = 0;

            for _ in 0..requests_per_task {
                let req_start = Instant::now();
                let res = client_clone
                    .post(url_clone.as_str())
                    .json(&serde_json::json!({"test": "payload"}))
                    .send()
                    .await;

                let elapsed = req_start.elapsed().as_secs_f64() * 1000.0;
                match res {
                    Ok(r) if r.status().is_success() => latencies.push(elapsed),
                    _ => errors += 1,
                }
            }

            (latencies, errors)
        });
        handles.push(handle);
    }

    let mut all_latencies = Vec::new();
    let mut total_errors = 0;

    for h in handles {
        let (lats, errs) = h.await.unwrap();
        all_latencies.extend(lats);
        total_errors += errs;
    }

    let total_elapsed = start_time.elapsed().as_secs_f64();
    let rps = (total_requests as f64) / total_elapsed;

    all_latencies.sort_by(|a, b| a.partial_cmp(b).unwrap());

    let p50 = percentile(&all_latencies, 50.0);
    let p95 = percentile(&all_latencies, 95.0);
    let p99 = percentile(&all_latencies, 99.0);
    let error_rate = (total_errors as f64 / total_requests as f64) * 100.0;

    BenchResults {
        rps,
        p50_ms: p50,
        p95_ms: p95,
        p99_ms: p99,
        error_rate,
    }
}

fn percentile(latencies: &[f64], pct: f64) -> f64 {
    if latencies.is_empty() {
        return 0.0;
    }
    let idx = ((pct / 100.0) * (latencies.len() as f64)) as usize;
    let clamped = idx.min(latencies.len() - 1);
    latencies[clamped]
}
