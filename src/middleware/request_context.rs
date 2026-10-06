use crate::audit::AuditEvent;
use crate::identity::model::ClientIdentity;
use crate::middleware::safe_headers::extract_safe_headers;
use axum::{
    body::Body,
    extract::Request,
    http::{HeaderValue, StatusCode},
    middleware::Next,
    response::Response,
};
use std::collections::HashMap;
use std::time::Instant;
use uuid::Uuid;

pub const HEADER_X_REQUEST_ID: &str = "x-request-id";

/// Context collected for an intercepted HTTP request.
#[derive(Debug, Clone)]
pub struct RequestContext {
    pub request_id: String,
    pub identity: ClientIdentity,
    pub method: String,
    pub uri_path: String,
    pub host: Option<String>,
    pub safe_headers: HashMap<String, String>,
    pub start_time: Instant,
    pub decision: String,
}

impl RequestContext {
    /// Constructs a new RequestContext from an incoming HTTP Request and ClientIdentity.
    pub fn from_request(req: &Request<Body>, identity: ClientIdentity) -> (Self, String) {
        let headers = req.headers();

        // Extract or generate Request ID
        let request_id = extract_or_generate_request_id(headers);

        let method = req.method().to_string();
        let uri_path = req
            .uri()
            .path_and_query()
            .map(|pq| pq.as_str())
            .unwrap_or_else(|| req.uri().path())
            .to_string();
        let host = headers
            .get(http::header::HOST)
            .and_then(|h| h.to_str().ok())
            .map(|s| s.to_string());
        let safe_headers = extract_safe_headers(headers);

        let ctx = Self {
            request_id: request_id.clone(),
            identity,
            method,
            uri_path,
            host,
            safe_headers,
            start_time: Instant::now(),
            decision: "ALLOW".to_string(), // Phase 1 default decision placeholder
        };

        (ctx, request_id)
    }

    /// Converts the request context into a structured AuditEvent upon request completion.
    pub fn to_audit_event(&self, status: Option<StatusCode>, elapsed_ms: u64) -> AuditEvent {
        AuditEvent::new(
            self.request_id.clone(),
            self.identity.identity.clone(),
            self.method.clone(),
            self.uri_path.clone(),
            self.decision.clone(),
            status.map(|s| s.as_u16()),
            Some(elapsed_ms),
        )
    }
}

/// Helper function to validate and extract existing request ID or generate a new UUID v4.
pub fn extract_or_generate_request_id(headers: &http::HeaderMap) -> String {
    if let Some(val) = headers.get(HEADER_X_REQUEST_ID) {
        if let Ok(s) = val.to_str() {
            let trimmed = s.trim();
            if is_valid_request_id(trimmed) {
                return trimmed.to_string();
            }
        }
    }
    Uuid::new_v4().to_string()
}

/// Checks if a candidate request ID is safe and valid.
fn is_valid_request_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 128
        && id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.')
}

/// Axum middleware that extracts ClientIdentity, creates RequestContext, sets X-Request-ID response header,
/// and emits structured audit logging.
pub async fn request_context_middleware(mut req: Request, next: Next) -> Response {
    let identity = req
        .extensions()
        .get::<ClientIdentity>()
        .cloned()
        .unwrap_or_else(ClientIdentity::anonymous);

    let (context, request_id) = RequestContext::from_request(&req, identity);

    req.extensions_mut().insert(context.clone());

    let mut response = next.run(req).await;

    // Propagate request ID in response headers
    if let Ok(hdr_val) = HeaderValue::from_str(&request_id) {
        response.headers_mut().insert(HEADER_X_REQUEST_ID, hdr_val);
    }

    let elapsed = context.start_time.elapsed().as_millis() as u64;
    let audit_event = context.to_audit_event(Some(response.status()), elapsed);
    audit_event.emit();

    response
}
