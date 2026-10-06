use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, IsCa, KeyPair, SanType,
};
use std::fs;
use std::path::Path;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let out_dir = Path::new("certs");
    if !out_dir.exists() {
        fs::create_dir_all(out_dir)?;
    }

    println!("Generating local development mTLS certificates in ./certs/...");
    println!("WARNING: THESE CERTIFICATES ARE FOR DEVELOPMENT AND TESTING ONLY!");

    // 1. Generate Local Root CA
    let mut ca_params = CertificateParams::default();
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let mut ca_dn = DistinguishedName::new();
    ca_dn.push(DnType::CommonName, "Arkion Local Dev Root CA");
    ca_dn.push(DnType::OrganizationName, "Arkion Dev Security");
    ca_params.distinguished_name = ca_dn;

    let ca_key = KeyPair::generate()?;
    let ca_cert = ca_params.self_signed(&ca_key)?;

    fs::write(out_dir.join("ca.crt"), ca_cert.pem())?;
    fs::write(out_dir.join("ca.key"), ca_key.serialize_pem())?;
    println!(" -> Generated certs/ca.crt & certs/ca.key");

    // 2. Generate Proxy Server Certificate (signed by Root CA)
    let mut server_params = CertificateParams::default();
    let mut server_dn = DistinguishedName::new();
    server_dn.push(DnType::CommonName, "localhost");
    server_params.distinguished_name = server_dn;
    server_params.subject_alt_names = vec![
        SanType::DnsName("localhost".try_into()?),
        SanType::IpAddress("127.0.0.1".parse()?),
    ];

    let server_key = KeyPair::generate()?;
    let server_cert = server_params.signed_by(&server_key, &ca_cert, &ca_key)?;

    fs::write(out_dir.join("server.crt"), server_cert.pem())?;
    fs::write(out_dir.join("server.key"), server_key.serialize_pem())?;
    println!(" -> Generated certs/server.crt & certs/server.key");

    // 3. Generate Valid Client Certificate with SPIFFE URI SAN
    let mut spiffe_params = CertificateParams::default();
    let mut spiffe_dn = DistinguishedName::new();
    spiffe_dn.push(DnType::CommonName, "spiffe-payment-agent");
    spiffe_dn.push(DnType::OrganizationName, "Customer A");
    spiffe_params.distinguished_name = spiffe_dn;
    let spiffe_uri: SanType = SanType::URI("spiffe://customer-a/prod/payment-agent".try_into()?);
    spiffe_params.subject_alt_names = vec![spiffe_uri];

    let spiffe_key = KeyPair::generate()?;
    let spiffe_cert = spiffe_params.signed_by(&spiffe_key, &ca_cert, &ca_key)?;

    fs::write(out_dir.join("client_spiffe.crt"), spiffe_cert.pem())?;
    fs::write(
        out_dir.join("client_spiffe.key"),
        spiffe_key.serialize_pem(),
    )?;
    println!(" -> Generated certs/client_spiffe.crt & certs/client_spiffe.key (Identity: spiffe://customer-a/prod/payment-agent)");

    // 4. Generate Valid Client Certificate without SPIFFE (Standard Subject identity)
    let mut std_params = CertificateParams::default();
    let mut std_dn = DistinguishedName::new();
    std_dn.push(DnType::CommonName, "standard-agent");
    std_dn.push(DnType::OrganizationName, "Customer B");
    std_params.distinguished_name = std_dn;

    let std_key = KeyPair::generate()?;
    let std_cert = std_params.signed_by(&std_key, &ca_cert, &ca_key)?;

    fs::write(out_dir.join("client_standard.crt"), std_cert.pem())?;
    fs::write(out_dir.join("client_standard.key"), std_key.serialize_pem())?;
    println!(" -> Generated certs/client_standard.crt & certs/client_standard.key");

    // 5. Generate Untrusted CA & Client Cert (for mTLS rejection testing)
    let mut untrusted_ca_params = CertificateParams::default();
    untrusted_ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let mut untrusted_ca_dn = DistinguishedName::new();
    untrusted_ca_dn.push(DnType::CommonName, "Untrusted Root CA");
    untrusted_ca_params.distinguished_name = untrusted_ca_dn;
    let untrusted_ca_key = KeyPair::generate()?;
    let untrusted_ca_cert = untrusted_ca_params.self_signed(&untrusted_ca_key)?;

    let mut untrusted_client_params = CertificateParams::default();
    let mut untrusted_client_dn = DistinguishedName::new();
    untrusted_client_dn.push(DnType::CommonName, "untrusted-agent");
    untrusted_client_params.distinguished_name = untrusted_client_dn;
    let untrusted_client_key = KeyPair::generate()?;
    let untrusted_client_cert = untrusted_client_params.signed_by(
        &untrusted_client_key,
        &untrusted_ca_cert,
        &untrusted_ca_key,
    )?;

    fs::write(out_dir.join("untrusted_ca.crt"), untrusted_ca_cert.pem())?;
    fs::write(
        out_dir.join("untrusted_client.crt"),
        untrusted_client_cert.pem(),
    )?;
    fs::write(
        out_dir.join("untrusted_client.key"),
        untrusted_client_key.serialize_pem(),
    )?;
    println!(" -> Generated certs/untrusted_client.crt & certs/untrusted_client.key");

    println!("\nDevelopment certificates successfully generated in ./certs/");
    Ok(())
}
