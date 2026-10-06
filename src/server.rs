use crate::authz::{authorization_middleware, PolicyEngine};
use crate::config::AppConfig;
use crate::error::ProxyError;
use crate::identity::extract_identity_from_der;
use crate::middleware::request_context_middleware;
use crate::proxy::ReverseProxy;
use crate::tls::create_mtls_server_config;
use crate::trust::DynamicClientCertVerifier;
use axum::{
    extract::{DefaultBodyLimit, Extension},
    http::StatusCode,
    response::{Html, IntoResponse, Json},
    routing::{get, post},
    Router,
};
use hyper_util::rt::TokioIo;
use hyper_util::server::conn::auto;
use serde_json::json;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;
use tracing::{error, info, warn};

pub struct ProxyServer {
    config: AppConfig,
    policy_engine: Arc<PolicyEngine>,
    trust_verifier: Option<Arc<DynamicClientCertVerifier>>,
    reverse_proxy: Option<Arc<ReverseProxy>>,
}

impl ProxyServer {
    pub fn new(config: AppConfig) -> Result<Self, ProxyError> {
        let policy_engine = if config.policy_path.exists() {
            Arc::new(PolicyEngine::from_file(&config.policy_path)?)
        } else {
            info!(
                "Policy file {:?} not found; initializing empty default-deny policy engine",
                config.policy_path
            );
            Arc::new(PolicyEngine::new(vec![]))
        };

        Ok(Self {
            config,
            policy_engine,
            trust_verifier: None,
            reverse_proxy: None,
        })
    }

    pub fn with_policy_engine(mut self, engine: PolicyEngine) -> Self {
        self.policy_engine = Arc::new(engine);
        self
    }

    pub fn trust_verifier(&self) -> Option<Arc<DynamicClientCertVerifier>> {
        self.trust_verifier.clone()
    }

    pub fn reverse_proxy(&self) -> Option<Arc<ReverseProxy>> {
        self.reverse_proxy.clone()
    }

    pub async fn run(mut self) -> Result<(), ProxyError> {
        let (tls_config, dynamic_verifier) = create_mtls_server_config(
            &self.config.server_cert_path,
            &self.config.server_key_path,
            &self.config.client_ca_cert_path,
        )?;

        self.trust_verifier = Some(dynamic_verifier.clone());

        let reverse_proxy = Arc::new(ReverseProxy::new(
            self.config.upstream_url.clone(),
            Duration::from_secs(self.config.upstream_timeout_secs),
            self.config.max_concurrent_requests,
            self.config.cb_failure_threshold,
            Duration::from_secs(self.config.cb_cooldown_secs),
        ));
        self.reverse_proxy = Some(reverse_proxy.clone());

        let acceptor = TlsAcceptor::from(tls_config);
        let addr = format!("{}:{}", self.config.proxy_host, self.config.proxy_port);
        let listener = TcpListener::bind(&addr).await?;

        let verifier_for_admin = dynamic_verifier.clone();
        let admin_reload_handler = move |body_bytes: axum::body::Bytes| {
            let verifier = verifier_for_admin.clone();
            async move {
                match verifier.reload_from_ca_pem(&body_bytes) {
                    Ok(count) => Json(json!({
                        "status": "success",
                        "message": format!("Trust store updated successfully with {count} root certificates"),
                        "active_roots": count
                    }))
                    .into_response(),
                    Err(err) => (
                        StatusCode::BAD_REQUEST,
                        Json(json!({
                            "error": "Trust Store Update Rejected",
                            "message": err.to_string()
                        })),
                    )
                        .into_response(),
                }
            }
        };

        let verifier_for_ready = dynamic_verifier.clone();
        let reverse_proxy_for_ready = reverse_proxy.clone();
        let readiness_handler = move || {
            let verifier = verifier_for_ready.clone();
            let proxy = reverse_proxy_for_ready.clone();
            async move {
                let roots_count = verifier.root_cert_count();
                let cb_state = proxy.circuit_breaker().state_name();
                if roots_count > 0 && cb_state != "OPEN" {
                    (
                        StatusCode::OK,
                        Json(json!({
                            "status": "ready",
                            "active_trust_roots": roots_count,
                            "circuit_breaker": cb_state
                        })),
                    )
                } else {
                    (
                        StatusCode::SERVICE_UNAVAILABLE,
                        Json(json!({
                            "status": "not_ready",
                            "active_trust_roots": roots_count,
                            "circuit_breaker": cb_state
                        })),
                    )
                }
            }
        };

        let verifier_for_dashboard = dynamic_verifier.clone();
        let proxy_for_dashboard = reverse_proxy.clone();
        let dashboard_summary_handler = move || {
            let verifier = verifier_for_dashboard.clone();
            let proxy = proxy_for_dashboard.clone();
            async move {
                Json(json!({
                    "project_name": "Arkion Identity-Aware Reverse Proxy",
                    "proxy_status": "ONLINE",
                    "active_trust_roots": verifier.root_cert_count(),
                    "circuit_breaker_state": proxy.circuit_breaker().state_name(),
                    "concurrency_limit": 1000,
                    "upstream_timeout_secs": 10
                }))
            }
        };

        let dashboard_ui_handler = || async { Html(include_str!("../ui/dashboard.html")) };

        // Local-only presentation HTTP server (e.g. http://127.0.0.1:8081/dashboard)
        let verifier_for_dashboard_http = dynamic_verifier.clone();
        let proxy_for_dashboard_http = reverse_proxy.clone();
        let dashboard_summary_http_handler = move || {
            let verifier = verifier_for_dashboard_http.clone();
            let proxy = proxy_for_dashboard_http.clone();
            async move {
                Json(json!({
                    "project_name": "Arkion Identity-Aware Reverse Proxy",
                    "proxy_status": "ONLINE",
                    "active_trust_roots": verifier.root_cert_count(),
                    "circuit_breaker_state": proxy.circuit_breaker().state_name(),
                    "concurrency_limit": 1000,
                    "upstream_timeout_secs": 10
                }))
            }
        };

        let verifier_for_ready_http = dynamic_verifier.clone();
        let proxy_for_ready_http = reverse_proxy.clone();
        let readiness_http_handler = move || {
            let verifier = verifier_for_ready_http.clone();
            let proxy = proxy_for_ready_http.clone();
            async move {
                let roots_count = verifier.root_cert_count();
                let cb_state = proxy.circuit_breaker().state_name();
                if roots_count > 0 && cb_state != "OPEN" {
                    (
                        StatusCode::OK,
                        Json(json!({
                            "status": "ready",
                            "active_trust_roots": roots_count,
                            "circuit_breaker": cb_state
                        })),
                    )
                } else {
                    (
                        StatusCode::SERVICE_UNAVAILABLE,
                        Json(json!({
                            "status": "not_ready",
                            "active_trust_roots": roots_count,
                            "circuit_breaker": cb_state
                        })),
                    )
                }
            }
        };

        let presentation_router = Router::new()
            .route("/", get(dashboard_ui_handler))
            .route("/dashboard", get(dashboard_ui_handler))
            .route("/ui", get(dashboard_ui_handler))
            .route(
                "/api/dashboard-summary",
                get(dashboard_summary_http_handler),
            )
            .route("/health", get(health_handler))
            .route("/ready", get(readiness_http_handler));

        let dashboard_addr = format!(
            "{}:{}",
            self.config.dashboard_host, self.config.dashboard_port
        );
        match TcpListener::bind(&dashboard_addr).await {
            Ok(dash_listener) => {
                info!(
                    "Local Presentation Dashboard HTTP server listening on http://{}/dashboard",
                    dashboard_addr
                );
                tokio::spawn(async move {
                    if let Err(e) = axum::serve(dash_listener, presentation_router).await {
                        error!("Presentation Dashboard HTTP server error: {}", e);
                    }
                });
            }
            Err(err) => {
                warn!(
                    "Could not bind presentation dashboard server to {}: {}",
                    dashboard_addr, err
                );
            }
        }

        let router = Router::new()
            .route("/health", get(health_handler))
            .route("/ready", get(readiness_handler))
            .route("/dashboard", get(dashboard_ui_handler))
            .route("/ui", get(dashboard_ui_handler))
            .route("/api/dashboard-summary", get(dashboard_summary_handler))
            .route("/admin/reload-trust", post(admin_reload_handler))
            .fallback(ReverseProxy::proxy_handler)
            .layer(Extension(reverse_proxy))
            .layer(axum::middleware::from_fn(authorization_middleware))
            .layer(Extension(self.policy_engine.clone()))
            .layer(axum::middleware::from_fn(request_context_middleware))
            .layer(DefaultBodyLimit::max(self.config.max_request_body_bytes));

        info!(
            "Arkion Identity-Aware mTLS Reverse Proxy listening on https://{}",
            addr
        );
        info!(
            "Presentation Dashboard UI available at http://{}/dashboard",
            dashboard_addr
        );
        info!("Configured Upstream Target: {}", self.config.upstream_url);

        loop {
            tokio::select! {
                accept_result = listener.accept() => {
                    let (tcp_stream, peer_addr) = match accept_result {
                        Ok(val) => val,
                        Err(err) => {
                            error!("TCP accept error: {}", err);
                            continue;
                        }
                    };

                    let acceptor = acceptor.clone();
                    let router = router.clone();

                    tokio::spawn(async move {
                        let tls_stream = match acceptor.accept(tcp_stream).await {
                            Ok(stream) => stream,
                            Err(err) => {
                                warn!("mTLS Handshake failed from {}: {}", peer_addr, err);
                                return;
                            }
                        };

                        let (_, session) = tls_stream.get_ref();
                        let identity = match session.peer_certificates().and_then(|certs| certs.first()) {
                            Some(cert) => match extract_identity_from_der(cert.as_ref()) {
                                Ok(id) => id,
                                Err(e) => {
                                    error!("Failed to extract identity from client cert: {}", e);
                                    return;
                                }
                            },
                            None => {
                                warn!("No client certificate presented by {}", peer_addr);
                                return;
                            }
                        };

                        info!(
                            "mTLS Authenticated Client: identity='{}' (spiffe={}) from {}",
                            identity.identity, identity.is_spiffe, peer_addr
                        );

                        let app = router.layer(Extension(identity));
                        let service = hyper_util::service::TowerToHyperService::new(app);

                        let io = TokioIo::new(tls_stream);
                        if let Err(err) = auto::Builder::new(hyper_util::rt::TokioExecutor::new())
                            .serve_connection(io, service)
                            .await
                        {
                            tracing::debug!("Connection closed: {}", err);
                        }
                    });
                }
                _ = tokio::signal::ctrl_c() => {
                    info!("Shutdown signal received (Ctrl+C). Initiating graceful shutdown...");
                    break;
                }
            }
        }

        info!("Arkion Identity-Aware Proxy cleanly shut down.");
        Ok(())
    }
}

async fn health_handler() -> impl IntoResponse {
    Json(json!({
        "status": "healthy",
        "service": "arkion-identity-proxy"
    }))
}
