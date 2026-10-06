use crate::error::ProxyError;
use crate::identity::model::ClientIdentity;
use x509_parser::prelude::*;

pub fn extract_identity_from_der(der: &[u8]) -> Result<ClientIdentity, ProxyError> {
    let (_, cert) = parse_x509_certificate(der)
        .map_err(|e| ProxyError::CertParse(format!("Failed to parse DER certificate: {e}")))?;

    let subject = cert.subject().to_string();
    let issuer = cert.issuer().to_string();
    let serial_number = format_serial(cert.raw_serial());

    let mut uri_sans = Vec::new();
    let mut dns_sans = Vec::new();

    if let Ok(Some(ext)) = cert.subject_alternative_name() {
        for name in &ext.value.general_names {
            match name {
                GeneralName::URI(uri) => {
                    uri_sans.push(uri.to_string());
                }
                GeneralName::DNSName(dns) => {
                    dns_sans.push(dns.to_string());
                }
                _ => {}
            }
        }
    }

    // Identify SPIFFE URI SAN (starts with "spiffe://")
    let spiffe_id = uri_sans
        .iter()
        .find(|uri| is_valid_spiffe_uri(uri))
        .cloned();

    let (identity, is_spiffe) = match spiffe_id {
        Some(spiffe) => (spiffe, true),
        None => (subject.clone(), false),
    };

    Ok(ClientIdentity {
        identity,
        subject,
        issuer,
        uri_sans,
        dns_sans,
        serial_number,
        is_spiffe,
    })
}

/// Validates whether a URI conforms to the SPIFFE ID format.
/// SPIFFE IDs must start with `spiffe://` and have a valid trust domain and path.
pub fn is_valid_spiffe_uri(uri: &str) -> bool {
    if !uri.starts_with("spiffe://") {
        return false;
    }
    let rest = &uri["spiffe://".len()..];
    if rest.is_empty() {
        return false;
    }
    let parts: Vec<&str> = rest.splitn(2, '/').collect();
    if parts[0].is_empty() {
        return false;
    }
    true
}

fn format_serial(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|b| format!("{b:02X}"))
        .collect::<Vec<_>>()
        .join(":")
}
