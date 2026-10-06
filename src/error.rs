use thiserror::Error;

#[derive(Error, Debug)]
pub enum ProxyError {
    #[error("Configuration error: {0}")]
    Config(String),

    #[error("TLS error: {0}")]
    Tls(String),

    #[error("Certificate parsing error: {0}")]
    CertParse(String),

    #[error("Identity extraction error: {0}")]
    Identity(String),

    #[error("Authorization denied: {0}")]
    AuthorizationDenied(String),

    #[error("Proxy loop detected: {0}")]
    ProxyLoop(String),

    #[error("Upstream error: {0}")]
    Upstream(String),

    #[error("Payload too large: {0}")]
    PayloadTooLarge(String),

    #[error("Trust store rotation error: {0}")]
    TrustRotation(String),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("HTTP error: {0}")]
    Http(String),
}
