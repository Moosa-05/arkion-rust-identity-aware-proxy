use crate::error::ProxyError;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AppConfig {
    pub proxy_host: String,
    pub proxy_port: u16,
    pub upstream_url: String,
    pub server_cert_path: PathBuf,
    pub server_key_path: PathBuf,
    pub client_ca_cert_path: PathBuf,
    pub policy_path: PathBuf,
    pub max_request_body_bytes: usize,
    pub enable_loop_prevention: bool,
    pub upstream_timeout_secs: u64,
    pub max_concurrent_requests: usize,
    pub cb_failure_threshold: u32,
    pub cb_cooldown_secs: u64,
    pub dashboard_host: String,
    pub dashboard_port: u16,
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            proxy_host: "127.0.0.1".to_string(),
            proxy_port: 8443,
            upstream_url: "http://127.0.0.1:8080".to_string(),
            server_cert_path: PathBuf::from("certs/server.crt"),
            server_key_path: PathBuf::from("certs/server.key"),
            client_ca_cert_path: PathBuf::from("certs/ca.crt"),
            policy_path: PathBuf::from("config/policy.yaml"),
            max_request_body_bytes: 10 * 1024 * 1024, // 10MB
            enable_loop_prevention: true,
            upstream_timeout_secs: 10,
            max_concurrent_requests: 1000,
            cb_failure_threshold: 5,
            cb_cooldown_secs: 10,
            dashboard_host: "127.0.0.1".to_string(),
            dashboard_port: 8081,
        }
    }
}

impl AppConfig {
    pub fn load() -> Result<Self, ProxyError> {
        let mut cfg = Self::default();

        if let Ok(host) = std::env::var("ARKION_PROXY_HOST") {
            cfg.proxy_host = host;
        }
        if let Ok(port) = std::env::var("ARKION_PROXY_PORT") {
            if let Ok(parsed) = port.parse::<u16>() {
                cfg.proxy_port = parsed;
            }
        }
        if let Ok(upstream) = std::env::var("ARKION_UPSTREAM_URL") {
            cfg.upstream_url = upstream;
        }
        if let Ok(cert) = std::env::var("ARKION_SERVER_CERT_PATH") {
            cfg.server_cert_path = PathBuf::from(cert);
        }
        if let Ok(key) = std::env::var("ARKION_SERVER_KEY_PATH") {
            cfg.server_key_path = PathBuf::from(key);
        }
        if let Ok(ca) = std::env::var("ARKION_CLIENT_CA_CERT_PATH") {
            cfg.client_ca_cert_path = PathBuf::from(ca);
        }
        if let Ok(pol) = std::env::var("ARKION_POLICY_PATH") {
            cfg.policy_path = PathBuf::from(pol);
        }
        if let Ok(max_bytes) = std::env::var("ARKION_MAX_BODY_BYTES") {
            if let Ok(parsed) = max_bytes.parse::<usize>() {
                cfg.max_request_body_bytes = parsed;
            }
        }
        if let Ok(timeout) = std::env::var("ARKION_UPSTREAM_TIMEOUT_SECS") {
            if let Ok(parsed) = timeout.parse::<u64>() {
                cfg.upstream_timeout_secs = parsed;
            }
        }
        if let Ok(concurrent) = std::env::var("ARKION_MAX_CONCURRENT_REQUESTS") {
            if let Ok(parsed) = concurrent.parse::<usize>() {
                cfg.max_concurrent_requests = parsed;
            }
        }
        if let Ok(d_host) = std::env::var("ARKION_DASHBOARD_HOST") {
            cfg.dashboard_host = d_host;
        }
        if let Ok(d_port) = std::env::var("ARKION_DASHBOARD_PORT") {
            if let Ok(parsed) = d_port.parse::<u16>() {
                cfg.dashboard_port = parsed;
            }
        }

        cfg.validate()?;

        Ok(cfg)
    }

    pub fn validate(&self) -> Result<(), ProxyError> {
        if self.enable_loop_prevention {
            let self_target_1 = format!("https://{}:{}", self.proxy_host, self.proxy_port);
            let self_target_2 = format!("http://{}:{}", self.proxy_host, self.proxy_port);
            let self_target_3 = format!("localhost:{}", self.proxy_port);
            let self_target_4 = format!("127.0.0.1:{}", self.proxy_port);

            if self.upstream_url == self_target_1
                || self.upstream_url == self_target_2
                || self.upstream_url.contains(&self_target_3)
                || self.upstream_url.contains(&self_target_4)
            {
                return Err(ProxyError::Config(format!(
                    "Upstream URL '{}' is self-referential to proxy listening on {}:{}. Proxy loop prevented.",
                    self.upstream_url, self.proxy_host, self.proxy_port
                )));
            }
        }

        Ok(())
    }
}
