use crate::error::ProxyError;
use parking_lot::RwLock;
use rustls::pki_types::{CertificateDer, UnixTime};
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use rustls::server::WebPkiClientVerifier;
use rustls::DistinguishedName;
use rustls::RootCertStore;
use std::sync::Arc;

#[derive(Debug)]
pub struct DynamicClientCertVerifier {
    active_verifier: RwLock<Arc<dyn ClientCertVerifier>>,
    root_cert_count: RwLock<usize>,
}

impl DynamicClientCertVerifier {
    pub fn new(initial_verifier: Arc<dyn ClientCertVerifier>, initial_count: usize) -> Self {
        Self {
            active_verifier: RwLock::new(initial_verifier),
            root_cert_count: RwLock::new(initial_count),
        }
    }

    pub fn reload_from_ca_pem(&self, ca_pem_bytes: &[u8]) -> Result<usize, ProxyError> {
        let mut reader = std::io::BufReader::new(ca_pem_bytes);
        let certs = rustls_pemfile::certs(&mut reader)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| {
                ProxyError::TrustRotation(format!("Failed to parse PEM certificates: {e}"))
            })?;

        if certs.is_empty() {
            return Err(ProxyError::TrustRotation(
                "Rejected trust update: CA PEM bundle contained zero valid root certificates."
                    .to_string(),
            ));
        }

        let mut root_store = RootCertStore::empty();
        let mut added_count = 0;
        for cert in certs {
            root_store.add(cert).map_err(|e| {
                ProxyError::TrustRotation(format!("Invalid root certificate in bundle: {e}"))
            })?;
            added_count += 1;
        }

        let new_verifier = WebPkiClientVerifier::builder(Arc::new(root_store))
            .build()
            .map_err(|e| {
                ProxyError::TrustRotation(format!("Failed to build client cert verifier: {e}"))
            })?;

        let mut active_lock = self.active_verifier.write();
        *active_lock = new_verifier;

        let mut count_lock = self.root_cert_count.write();
        *count_lock = added_count;

        tracing::info!(
            "Dynamic trust store successfully reloaded with {} root CA certificates.",
            added_count
        );

        Ok(added_count)
    }

    pub fn root_cert_count(&self) -> usize {
        *self.root_cert_count.read()
    }
}

impl ClientCertVerifier for DynamicClientCertVerifier {
    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        &[]
    }

    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        now: UnixTime,
    ) -> Result<ClientCertVerified, rustls::Error> {
        let verifier = self.active_verifier.read().clone();
        verifier.verify_client_cert(end_entity, intermediates, now)
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        let verifier = self.active_verifier.read().clone();
        verifier.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        let verifier = self.active_verifier.read().clone();
        verifier.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        let verifier = self.active_verifier.read().clone();
        verifier.supported_verify_schemes()
    }
}
