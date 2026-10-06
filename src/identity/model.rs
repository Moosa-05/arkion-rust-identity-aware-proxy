use serde::{Deserialize, Serialize};

/// Internal identity model extracted from validated client mTLS certificate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClientIdentity {
    /// Primary authenticated non-human identity (SPIFFE URI if present, otherwise Subject)
    pub identity: String,
    /// Certificate Subject Distinguished Name
    pub subject: String,
    /// Certificate Issuer Distinguished Name
    pub issuer: String,
    /// URI Subject Alternative Names
    pub uri_sans: Vec<String>,
    /// DNS Subject Alternative Names
    pub dns_sans: Vec<String>,
    /// Certificate Serial Number (hex formatted)
    pub serial_number: String,
    /// Indicates if identity was extracted from a valid SPIFFE URI SAN
    pub is_spiffe: bool,
}

impl ClientIdentity {
    pub fn anonymous() -> Self {
        Self {
            identity: "anonymous".to_string(),
            subject: "unknown".to_string(),
            issuer: "unknown".to_string(),
            uri_sans: Vec::new(),
            dns_sans: Vec::new(),
            serial_number: "unknown".to_string(),
            is_spiffe: false,
        }
    }
}
