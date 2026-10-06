use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuditEvent {
    pub request_id: String,
    pub identity: String,
    pub method: String,
    pub path: String,
    pub decision: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub upstream_status: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub latency_ms: Option<u64>,
}

impl AuditEvent {
    pub fn new(
        request_id: impl Into<String>,
        identity: impl Into<String>,
        method: impl Into<String>,
        path: impl Into<String>,
        decision: impl Into<String>,
        upstream_status: Option<u16>,
        latency_ms: Option<u64>,
    ) -> Self {
        Self {
            request_id: request_id.into(),
            identity: identity.into(),
            method: method.into(),
            path: path.into(),
            decision: decision.into(),
            upstream_status,
            latency_ms,
        }
    }

    /// Logs the structured audit event as JSON via tracing.
    pub fn emit(&self) {
        if let Ok(json) = serde_json::to_string(self) {
            tracing::info!(target: "audit", audit_event = %json, "AUDIT_EVENT");
        }
    }
}
