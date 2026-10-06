use crate::middleware::request_context::RequestContext;
use crate::proxy::headers::{
    clean_hop_by_hop_headers, sanitize_and_apply_forwarded_headers, HEADER_PROXY_LOOP,
};
use crate::resilience::CircuitBreaker;
use axum::{
    body::Body,
    extract::{Extension, Request},
    http::StatusCode,
    response::{IntoResponse, Json, Response},
};
use reqwest::Client;
use serde_json::json;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Semaphore;

#[derive(Clone)]
pub struct ReverseProxy {
    client: Client,
    upstream_base_url: String,
    upstream_timeout: Duration,
    concurrency_semaphore: Arc<Semaphore>,
    circuit_breaker: CircuitBreaker,
}

impl ReverseProxy {
    pub fn new(
        upstream_base_url: String,
        upstream_timeout: Duration,
        max_concurrent_requests: usize,
        failure_threshold: u32,
        cooldown_duration: Duration,
    ) -> Self {
        let client = Client::builder()
            .redirect(reqwest::redirect::Policy::none()) // Explicitly disable automatic retries/redirects
            .build()
            .expect("Failed to build HTTP reverse proxy client");

        Self {
            client,
            upstream_base_url: upstream_base_url.trim_end_matches('/').to_string(),
            upstream_timeout,
            concurrency_semaphore: Arc::new(Semaphore::new(max_concurrent_requests)),
            circuit_breaker: CircuitBreaker::new(failure_threshold, cooldown_duration),
        }
    }

    pub fn circuit_breaker(&self) -> &CircuitBreaker {
        &self.circuit_breaker
    }

    pub async fn proxy_handler(
        Extension(proxy): Extension<Arc<ReverseProxy>>,
        Extension(ctx): Extension<RequestContext>,
        req: Request<Body>,
    ) -> Response {
        // 1. Loop detection check
        if req.headers().contains_key(HEADER_PROXY_LOOP) {
            tracing::error!(
                "Proxy loop detected for request_id='{}' path='{}'",
                ctx.request_id,
                ctx.uri_path
            );
            return (
                StatusCode::LOOP_DETECTED,
                Json(json!({
                    "error": "Loop Detected",
                    "message": "Direct self-referential proxy loop detected."
                })),
            )
                .into_response();
        }

        // 2. Concurrency Limit Check
        let _permit = match proxy.concurrency_semaphore.try_acquire() {
            Ok(permit) => permit,
            Err(_) => {
                tracing::warn!(
                    "Concurrency limit reached for request_id='{}'",
                    ctx.request_id
                );
                return (
                    StatusCode::SERVICE_UNAVAILABLE,
                    Json(json!({
                        "error": "Service Unavailable",
                        "message": "Proxy concurrency limit reached. Please try again later."
                    })),
                )
                    .into_response();
            }
        };

        // 3. Circuit Breaker State Check (Fast-fail if OPEN)
        if let Err(cb_err) = proxy.circuit_breaker.check_allow() {
            tracing::warn!(
                "Circuit breaker fast-fail for request_id='{}': {}",
                ctx.request_id,
                cb_err
            );
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(json!({
                    "error": "Service Unavailable",
                    "message": cb_err.to_string()
                })),
            )
                .into_response();
        }

        // 4. Build target URL
        let target_url = format!("{}{}", proxy.upstream_base_url, ctx.uri_path);

        // 5. Deconstruct incoming request
        let (mut parts, body) = req.into_parts();

        // 6. Clean hop-by-hop headers
        clean_hop_by_hop_headers(&mut parts.headers);

        // 7. Apply proxy-derived forwarded headers & loop detection marker
        let peer_ip = ctx.host.as_deref().unwrap_or("127.0.0.1");
        sanitize_and_apply_forwarded_headers(
            &mut parts.headers,
            peer_ip,
            ctx.host.as_deref(),
            &ctx.identity.identity,
        );

        // 8. Build reqwest outgoing proxy request
        let mut req_builder = proxy
            .client
            .request(parts.method.clone(), &target_url)
            .headers(parts.headers);

        let body_stream = body.into_data_stream();
        req_builder = req_builder.body(reqwest::Body::wrap_stream(body_stream));

        // 9. Send request to upstream with timeout and circuit breaker tracking
        let send_future = req_builder.send();

        match tokio::time::timeout(proxy.upstream_timeout, send_future).await {
            Ok(Ok(upstream_res)) => {
                let status = upstream_res.status();

                // If upstream returns 5xx server error, record as failure in circuit breaker
                if status.is_server_error() {
                    proxy.circuit_breaker.record_result(false);
                } else {
                    proxy.circuit_breaker.record_result(true);
                }

                let mut resp_builder = Response::builder().status(status);

                if let Some(headers_mut) = resp_builder.headers_mut() {
                    for (k, v) in upstream_res.headers() {
                        headers_mut.insert(k, v.clone());
                    }
                    clean_hop_by_hop_headers(headers_mut);
                }

                let resp_stream = upstream_res.bytes_stream();
                let response_body = Body::from_stream(resp_stream);

                match resp_builder.body(response_body) {
                    Ok(res) => res,
                    Err(err) => (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Json(json!({
                            "error": "Proxy Response Error",
                            "message": format!("Failed to build response: {err}")
                        })),
                    )
                        .into_response(),
                }
            }
            Ok(Err(err)) => {
                proxy.circuit_breaker.record_result(false);
                tracing::error!("Upstream connection error to {}: {}", target_url, err);
                (
                    StatusCode::BAD_GATEWAY,
                    Json(json!({
                        "error": "Bad Gateway",
                        "message": format!("Upstream service unreachable or error: {err}")
                    })),
                )
                    .into_response()
            }
            Err(_elapsed) => {
                proxy.circuit_breaker.record_result(false);
                tracing::error!(
                    "Upstream request timed out after {:?} for target {}",
                    proxy.upstream_timeout,
                    target_url
                );
                (
                    StatusCode::GATEWAY_TIMEOUT,
                    Json(json!({
                        "error": "Gateway Timeout",
                        "message": format!("Upstream request timed out after {:?}", proxy.upstream_timeout)
                    })),
                )
                    .into_response()
            }
        }
    }
}
