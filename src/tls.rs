use crate::error::ProxyError;
use crate::trust::DynamicClientCertVerifier;
use rustls::server::WebPkiClientVerifier;
use rustls::RootCertStore;
use rustls_pki_types::{CertificateDer, PrivateKeyDer};
use std::fs::File;
use std::io::BufReader;
use std::path::Path;
use std::sync::Arc;

pub fn load_certs(path: &Path) -> Result<Vec<CertificateDer<'static>>, ProxyError> {
    let certfile = File::open(path)
        .map_err(|e| ProxyError::Tls(format!("Failed to open cert file {:?}: {e}", path)))?;
    let mut reader = BufReader::new(certfile);
    let certs = rustls_pemfile::certs(&mut reader)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| ProxyError::Tls(format!("Failed to parse certs in {:?}: {e}", path)))?;

    if certs.is_empty() {
        return Err(ProxyError::Tls(format!(
            "No certificates found in {:?}",
            path
        )));
    }

    Ok(certs)
}

pub fn load_private_key(path: &Path) -> Result<PrivateKeyDer<'static>, ProxyError> {
    let keyfile = File::open(path)
        .map_err(|e| ProxyError::Tls(format!("Failed to open key file {:?}: {e}", path)))?;
    let mut reader = BufReader::new(keyfile);
    let key = rustls_pemfile::private_key(&mut reader)
        .map_err(|e| ProxyError::Tls(format!("Failed to parse private key in {:?}: {e}", path)))?
        .ok_or_else(|| ProxyError::Tls(format!("No private key found in {:?}", path)))?;

    Ok(key)
}

/// Creates rustls ServerConfig configured with DynamicClientCertVerifier to support zero-downtime CA trust store rotation.
pub fn create_mtls_server_config(
    cert_path: &Path,
    key_path: &Path,
    ca_cert_path: &Path,
) -> Result<(Arc<rustls::ServerConfig>, Arc<DynamicClientCertVerifier>), ProxyError> {
    let server_certs = load_certs(cert_path)?;
    let server_key = load_private_key(key_path)?;
    let ca_certs = load_certs(ca_cert_path)?;
    let ca_count = ca_certs.len();

    let mut client_root_store = RootCertStore::empty();
    for ca in ca_certs {
        client_root_store
            .add(ca)
            .map_err(|e| ProxyError::Tls(format!("Failed to add CA root certificate: {e}")))?;
    }

    let initial_verifier = WebPkiClientVerifier::builder(Arc::new(client_root_store))
        .build()
        .map_err(|e| ProxyError::Tls(format!("Failed to build client cert verifier: {e}")))?;

    let dynamic_verifier = Arc::new(DynamicClientCertVerifier::new(initial_verifier, ca_count));

    let mut server_config = rustls::ServerConfig::builder()
        .with_client_cert_verifier(dynamic_verifier.clone())
        .with_single_cert(server_certs, server_key)
        .map_err(|e| ProxyError::Tls(format!("Failed to configure TLS server certificate: {e}")))?;

    server_config.alpn_protocols = vec![b"http/1.1".to_vec()];

    Ok((Arc::new(server_config), dynamic_verifier))
}
