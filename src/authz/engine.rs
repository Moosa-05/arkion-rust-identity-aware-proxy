use crate::authz::model::{IdentityPolicy, PolicyFile};
use crate::error::ProxyError;
use percent_encoding::percent_decode_str;
use std::path::Path;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    Allow,
    Deny,
}

impl Decision {
    pub fn as_str(&self) -> &'static str {
        match self {
            Decision::Allow => "ALLOW",
            Decision::Deny => "DENY",
        }
    }
}

#[derive(Debug, Clone)]
pub struct PolicyEngine {
    policies: Vec<IdentityPolicy>,
}

impl PolicyEngine {
    pub fn new(policies: Vec<IdentityPolicy>) -> Self {
        Self { policies }
    }

    pub fn from_yaml_str(yaml: &str) -> Result<Self, ProxyError> {
        let file: PolicyFile = serde_yaml::from_str(yaml)
            .map_err(|e| ProxyError::Config(format!("Failed to parse YAML policy: {e}")))?;
        Ok(Self::new(file.policies))
    }

    pub fn from_file(path: &Path) -> Result<Self, ProxyError> {
        let content = std::fs::read_to_string(path).map_err(|e| {
            ProxyError::Config(format!("Failed to read policy file {:?}: {e}", path))
        })?;

        if path.extension().and_then(|ext| ext.to_str()) == Some("json") {
            let file: PolicyFile = serde_json::from_str(&content)
                .map_err(|e| ProxyError::Config(format!("Failed to parse JSON policy: {e}")))?;
            Ok(Self::new(file.policies))
        } else {
            Self::from_yaml_str(&content)
        }
    }

    pub fn evaluate(&self, identity: &str, method: &str, raw_path: &str) -> Decision {
        let normalized_path = normalize_path(raw_path);
        let req_method = method.to_uppercase();

        for policy in &self.policies {
            if matches_identity(&policy.identity, identity) {
                for rule in &policy.allow {
                    if matches_method(&rule.method, &req_method)
                        && matches_path(&rule.path, &normalized_path)
                    {
                        return Decision::Allow;
                    }
                }
            }
        }

        Decision::Deny
    }
}

pub fn matches_identity(rule_identity: &str, req_identity: &str) -> bool {
    if rule_identity == "*" {
        return true;
    }
    rule_identity == req_identity
}

pub fn matches_method(rule_method: &str, req_method: &str) -> bool {
    if rule_method == "*" {
        return true;
    }
    rule_method.eq_ignore_ascii_case(req_method)
}

pub fn matches_path(rule_path: &str, normalized_req_path: &str) -> bool {
    if rule_path == "*" || rule_path == "/*" {
        return true;
    }

    if let Some(base_prefix) = rule_path.strip_suffix("/*") {
        let norm_base = normalize_path(base_prefix);
        let prefix = if norm_base == "/" {
            "/".to_string()
        } else {
            format!("{}/", norm_base)
        };
        return normalized_req_path.starts_with(&prefix);
    }

    let norm_rule = normalize_path(rule_path);
    norm_rule == normalized_req_path
}

/// Secure path normalization canonicalizing percent-encoding, duplicate slashes, and `.`/`..` path traversal segments.
pub fn normalize_path(raw_path: &str) -> String {
    let path_only = raw_path.split('?').next().unwrap_or(raw_path);
    let path_only = path_only.split('#').next().unwrap_or(path_only);

    let decoded = percent_decode_str(path_only).decode_utf8_lossy();

    let mut segments: Vec<&str> = Vec::new();

    for segment in decoded.split('/') {
        match segment {
            "" | "." => continue,
            ".." => {
                segments.pop();
            }
            normal => {
                segments.push(normal);
            }
        }
    }

    if segments.is_empty() {
        "/".to_string()
    } else {
        format!("/{}", segments.join("/"))
    }
}
