# Arkion Rust Identity-Aware TLS Reverse Proxy

[![Rust](https://img.shields.io/badge/Rust-1.97%2B-blue.svg)](https://www.rust-lang.org/)
[![mTLS](https://img.shields.io/badge/mTLS-Mandatory-green.svg)]()
[![SPIFFE](https://img.shields.io/badge/SPIFFE-Supported-orange.svg)]()

Production-oriented, zero-trust, identity-aware mTLS reverse proxy built with async Rust, Tokio, Axum, and Rustls.

---

## 1. Project Overview

The **Arkion Identity-Aware Proxy** sits in front of existing microservices and API backends, enforcing mandatory mutual TLS (mTLS) client certificate authentication, cryptographically extracting Non-Human Identities (NHI, such as SPIFFE IDs), enforcing fine-grained YAML/JSON authorization policies, sanitizing forwarded headers, preventing proxy loops, limiting payload sizes, and streaming traffic directly to upstream services.

---

## 2. Assignment Objective

Build a resilient, high-performance, identity-aware reverse proxy that satisfies:
- Inbound HTTPS/mTLS interception.
- SPIFFE URI SAN & Subject identity extraction.
- Deterministic, secure authorization policy evaluation.
- Streaming reverse proxying with hop-by-hop header removal.
- Dynamic zero-downtime CA trust-store rotation.
- Enterprise resilience suite (upstream timeout, concurrency limits, circuit breaker, health/readiness probes, and graceful shutdown).

---

## 3. Architecture

The proxy architecture cleanly separates **TLS-Layer Cryptographic Validation** from **Application Middleware Identity & Access Policy Processing**:

```
Client
  │
  │ TLS 1.2 / 1.3 + mTLS (Validated by rustls against Root CA)
  ▼
[ Intercept ] ──▶ [ Identify ] ──▶ [ Authorize ] ──▶ [ Observe ]
  Inbound HTTPS      Extract SPIFFE    Match YAML Policy   Audit Event Log
  Listener           URI SAN / Subject (ALLOW / DENY)     & Metrics
                                            │
                                      ALLOW │ (DENY -> 403 Forbidden)
                                            ▼
                                     Existing API / Upstream
```

---

## 4. Request Flow Pipeline

1. **Client Connection & mTLS Handshake**: Inbound connection over HTTPS. Rustls verifies that the client presents a valid X.509 certificate signed by the active Root CA store.
2. **Identity Extraction**: Extracts `ClientIdentity` (primary SPIFFE URI SAN if present, otherwise Subject DN), Serial Number, Issuer, and SANs.
3. **Request Context Collection**: Generates or propagates `X-Request-ID`, captures method, path, host, start time, and filters safe headers.
4. **Authorization Middleware**: Evaluates `PolicyEngine` against `(identity, method, path)`. If denied, returns `403 Forbidden` and emits an audit event.
5. **Resilience & Pre-Forwarding Checks**:
   - Checks `X-Arkion-Proxy-Loop` header (returns `508 Loop Detected` if present).
   - Acquires concurrency semaphore slot (returns `503 Service Unavailable` if capacity exhausted).
   - Checks `CircuitBreaker` state (returns `503 Service Unavailable` if OPEN).
6. **Header Sanitization**: Strips hop-by-hop headers (`Connection`, `Keep-Alive`, `Upgrade`, etc.) and attaches proxy-derived metadata (`X-Forwarded-For`, `X-Forwarded-Host`, `X-Forwarded-Proto`, `X-Authenticated-Identity`).
7. **Streaming Forwarding**: Streams request body to upstream with configurable timeout (`504 Gateway Timeout` if exceeded).
8. **Response Return & Audit Emit**: Strips hop-by-hop headers from upstream response, sets `X-Request-ID`, streams response to client, and logs `AuditEvent`.

---

## 5. Project Structure

```
arkion-rust-identity-aware-proxy/
├── Cargo.toml                  # Cargo manifest and dependencies
├── Dockerfile                  # Multi-stage production Dockerfile
├── docker-compose.yml          # Compose setup for proxy & mock upstream
├── config/
│   └── policy.yaml             # Authorization policy rules
├── certs/                      # Development & test certificates directory
├── src/
│   ├── main.rs                 # Main binary entry point
│   ├── lib.rs                  # Library root re-exports
│   ├── config.rs               # Environment & file configuration
│   ├── error.rs                # Domain ProxyError enumerations
│   ├── audit.rs                # Structured AuditEvent model & logger
│   ├── tls.rs                  # mTLS rustls ServerConfig builder
│   ├── server.rs               # ProxyServer TCP listener & Axum router
│   ├── bin/
│   │   ├── generate_certs.rs   # Cross-platform mTLS cert generator tool
│   │   └── benchmark.rs        # Reproducible local performance benchmark
│   ├── identity/
│   │   ├── mod.rs
│   │   ├── model.rs            # ClientIdentity data model
│   │   └── extractor.rs        # X.509 DER parser & SPIFFE extractor
│   ├── authz/
│   │   ├── mod.rs
│   │   ├── model.rs            # PolicyFile & AllowRule schemas
│   │   ├── engine.rs           # PolicyEngine & path normalization
│   │   └── middleware.rs       # Authorization middleware layer
│   ├── proxy/
│   │   ├── mod.rs
│   │   ├── forwarder.rs        # ReverseProxy streaming forwarder
│   │   └── headers.rs          # Hop-by-hop filtering & forwarded metadata
│   ├── trust/
│   │   ├── mod.rs
│   │   └── rotator.rs          # DynamicClientCertVerifier hot-swapping
│   └── resilience/
│       ├── mod.rs
│       └── circuit_breaker.rs  # Thread-safe CircuitBreaker implementation
└── tests/
    ├── identity_and_audit_tests.rs
    ├── mtls_server_tests.rs
    ├── policy_and_trust_tests.rs
    ├── phase2_integration_tests.rs
    └── phase3_resilience_tests.rs
```

---

## 6. Build Instructions

Ensure Rust 1.97+ is installed:

```bash
cargo build --release
```

---

## 7. Run Instructions

1. Generate local development test certificates:
```bash
cargo run --bin generate_certs
```

2. Start the proxy server:
```bash
cargo run --bin arkion-identity-proxy
```

---

## 8. Configuration

Configured via environment variables or default values:

| Environment Variable | Default Value | Description |
|---|---|---|
| `ARKION_PROXY_HOST` | `127.0.0.1` | Host address to bind proxy listener |
| `ARKION_PROXY_PORT` | `8443` | HTTPS / mTLS port |
| `ARKION_UPSTREAM_URL` | `http://backend:8080` | Target upstream API URL |
| `ARKION_SERVER_CERT_PATH` | `certs/server.crt` | Server TLS certificate path |
| `ARKION_SERVER_KEY_PATH` | `certs/server.key` | Server TLS private key path |
| `ARKION_CLIENT_CA_CERT_PATH` | `certs/ca.crt` | Trusted Root CA bundle path |
| `ARKION_POLICY_PATH` | `config/policy.yaml` | Authorization policy file path |
| `ARKION_MAX_BODY_BYTES` | `10485760` (10MB) | Max request payload size limit |
| `ARKION_UPSTREAM_TIMEOUT_SECS` | `10` | Upstream request timeout in seconds |
| `ARKION_MAX_CONCURRENT_REQUESTS` | `1000` | Max concurrent in-flight requests |

---

## 9. Local Certificate Generation

To generate development/testing certificates without requiring OpenSSL:

```bash
cargo run --bin generate_certs
```

Generates in `./certs/`:
- `ca.crt` & `ca.key` (Root CA)
- `server.crt` & `server.key` (Server TLS certificate for `localhost` & `127.0.0.1`)
- `client_spiffe.crt` & `client_spiffe.key` (SPIFFE Identity: `spiffe://customer-a/prod/payment-agent`)
- `client_standard.crt` & `client_standard.key` (Standard Common Name client cert)
- `untrusted_client.crt` & `untrusted_client.key` (Invalid client cert signed by untrusted CA)

> **WARNING**: These generated certificates are for local development and testing only! Never use them in production.

---

## 10. mTLS Design

The proxy mandates mTLS at the transport layer. Connecting clients **must** present a valid X.509 certificate signed by a trusted CA configured in `client_ca_cert_path`. Unauthenticated connections are dropped at the TLS layer before reaching application code.

---

## 11. Client Certificate Validation

Certificate validation is handled natively by `rustls::server::WebPkiClientVerifier`, enforcing:
- Full CA trust chain verification up to the configured Root CA.
- Expiry date (`notBefore` and `notAfter`) checks.
- Cryptographic signature verification.

---

## 12. SPIFFE Identity Extraction

When a client presents a validated certificate:
- `x509-parser` inspects the X.509 extensions.
- Looks for `GeneralName::URI` in the Subject Alternative Name (SAN) extension.
- Validates if any URI SAN begins with `spiffe://` scheme.
- If a valid SPIFFE URI SAN exists (e.g. `spiffe://customer-a/prod/payment-agent`), it is used as the authenticated Non-Human Identity (NHI).
- If no SPIFFE URI SAN exists, fallback is set to the certificate's Subject Distinguished Name.

---

## 13. TLS Validation vs Middleware Validation

| Layer | Responsibility | Output / Action |
|---|---|---|
| **TLS Layer (Rustls)** | Cryptographic cert verification, CA signature validation, cipher negotiation | Rejects untrusted clients during TLS handshake |
| **App Middleware** | Extracting identity, path normalization, policy evaluation, audit logging | Allows/denies access (`403 Forbidden`), records audit events |

*Arbitrary client HTTP headers (such as `X-Client-Cert` or `X-Identity`) are NEVER trusted.* Identity comes exclusively from the validated TLS session state.

---

## 14. Authorization Policy Format

Policies are defined in YAML (`config/policy.yaml`) or JSON:

```yaml
policies:
  - identity: "spiffe://customer-a/prod/payment-agent"
    allow:
      - method: POST
        path: "/payments"
      - method: GET
        path: "/payments/*"

  - identity: "spiffe://customer-a/prod/reporting-agent"
    allow:
      - method: GET
        path: "/reports/*"

  - identity: "*"
    allow:
      - method: GET
        path: "/health"
```

---

## 15. Path Matching Semantics

- **Exact Match**: `path: "/payments"` matches `/payments` only.
- **Prefix Wildcard Match**: `path: "/reports/*"` matches `/reports/daily`, `/reports/123/summary`, but NOT `/reports` (without trailing slash) and NOT `/reports_secret`.
- **Universal Wildcard Match**: `path: "*"` or `path: "/*"` matches all paths.
- **Default Deny**: Any request not explicitly matched by an identity rule evaluates to `DENY` (`403 Forbidden`).

---

## 16. Authorization Bypass Protections

To prevent security bypasses caused by path manipulation:
1. **URL Decoding**: Percent-encoded sequences (e.g. `%2F`, `%2E%2E`) are decoded before rule evaluation.
2. **Canonicalization**: Dot segments (`.` and `..`) are resolved. For example, `/reports/../payments` is canonicalized to `/payments` before policy evaluation.
3. **Slash Normalization**: Duplicate slashes (`//payments///123` -> `/payments/123`) are collapsed.

---

## 17. Reverse Proxy Behavior

The proxy forwards authorized requests using `reqwest::Client` with connection pooling and streaming:
- Method, path, query parameters, and body streams are preserved.
- Outbound responses are streamed back to the client without loading full payloads into RAM.

---

## 18. Forwarded Header Handling

Client-supplied `Forwarded` and `X-Forwarded-*` headers are stripped to prevent header spoofing. The proxy injects trusted proxy-derived headers:
- `X-Forwarded-For`: Client IP address.
- `X-Forwarded-Host`: Original host header.
- `X-Forwarded-Proto`: `https`.
- `X-Authenticated-Identity`: Authenticated mTLS identity.

---

## 19. Hop-by-Hop Header Handling

Hop-by-hop headers are stripped before forwarding requests to upstream and before returning responses to clients:
`Connection`, `Keep-Alive`, `Proxy-Authenticate`, `Proxy-Authorization`, `TE`, `Trailer`, `Transfer-Encoding`, `Upgrade`, and any custom headers listed in the `Connection` header value.

---

## 20. Proxy Loop Prevention

- Injects an internal marker header `X-Arkion-Proxy-Loop: 1` into outgoing proxy requests.
- Rejects any incoming request containing `X-Arkion-Proxy-Loop` with `508 Loop Detected`.
- Rejects self-referential upstream URLs (where upstream points back to the proxy's own host and port).

---

## 21. Streaming Behavior

Both request and response bodies use chunked/streamed transfer (`axum::body::Body::into_data_stream()` and `reqwest::Body::wrap_stream()`), maintaining low memory usage even under large payloads.

---

## 22. Request Body Limits

Request payloads are constrained by `DefaultBodyLimit::max(max_bytes)` (default: 10MB). Requests exceeding this limit return `413 Payload Too Large`.

---

## 23. HTTP Protocol Assumptions

- Inbound: HTTP/1.1 over TLS 1.2/1.3.
- Outbound: HTTP/1.1 to configured upstream target.

---

## 24. Dynamic Trust Store Rotation

The proxy supports runtime Root CA certificate hot-reloading without process restarts via `DynamicClientCertVerifier`.

Trigger reload via admin endpoint:
```bash
curl -k --cert certs/client_spiffe.crt --key certs/client_spiffe.key \
     --data-binary "@certs/ca.crt" \
     https://localhost:8443/admin/reload-trust
```

---

## 25. Concurrency Safety During Trust Rotation

`DynamicClientCertVerifier` stores active verifiers inside a `parking_lot::RwLock<Arc<dyn ClientCertVerifier>>`. Handshakes acquire read locks; updates acquire a write lock to perform an atomic swap.

---

## 26. Existing TLS Connection Behavior During Trust Changes

Established TLS sessions continue uninterrupted. New TLS connections immediately use the newly swapped Root CA trust store.

---

## 27. Invalid Trust Update Handling

If a submitted CA PEM bundle is malformed or contains 0 valid root certs, the update is rejected with `400 Bad Request`. The existing active verifier remains active.

---

## 28. Rollback Behavior

Rollback is achieved by re-posting the previous known-good CA PEM bundle to `/admin/reload-trust`.

---

## 29. Fleet-Wide Trust Distribution

In production, trust rotation bundles can be distributed across proxy instances via Kubernetes ConfigMaps, automated cert-manager webhooks, or centralized secrets managers.

---

## 30. Resilience Mechanisms

1. **Upstream Timeout**: Configurable timeout (`10s` default). Returns `504 Gateway Timeout`.
2. **Concurrency Limit**: Limit on concurrent requests via `tokio::sync::Semaphore` (default: 1000). Returns `503 Service Unavailable`.
3. **Circuit Breaker**: `CLOSED -> OPEN -> HALF-OPEN -> CLOSED` states. Fast-fails requests with `503 Service Unavailable` when upstream is failing.
4. **Health & Readiness Probes**: `/health` (liveness) and `/ready` (readiness).
5. **Graceful Shutdown**: Intercepts `Ctrl+C` / `SIGTERM`, stops accepting new connections, and cleanly drains active connections.

---

## 31. Retry Safety

Automatic retries are **explicitly disabled** for non-idempotent HTTP methods (`POST`, `PUT`, `DELETE`, `PATCH`). Automatically retrying non-idempotent requests on network glitches can cause duplicate side-effects (e.g. charging a payment twice).

---

## 32. Health & Readiness Behavior

- `GET /health`: Returns `200 OK` (`{"status": "healthy"}`) to confirm process liveness.
- `GET /ready`: Returns `200 OK` (`{"status": "ready"}`) if active CA trust roots exist and circuit breaker is not OPEN.

---

## 33. Graceful Shutdown

Upon receiving `SIGINT` / `Ctrl+C`:
1. Proxy stops calling `listener.accept()`.
2. Active connection tasks complete naturally.
3. Process exits cleanly with code 0.

---

## 34. Security Considerations

- **Safe Logging**: `Authorization`, `Cookie`, `Set-Cookie`, `x-api-key`, and private keys are strictly excluded from logs.
- **Non-Root Container**: Container runs as unprivileged user `proxyuser` (UID 10001).

---

## 35. Known Limitations

- CRL/OCSP certificate revocation checking is not implemented.
- Outbound upstream connection uses HTTP/1.1.

---

## 36. Performance Methodology

Measured using `cargo run --bin benchmark`, running 300 requests across 10 concurrent async tasks comparing direct HTTP vs mTLS proxy forwarding.

---

## 37. Real Measured Benchmark Results

```
==================================================
BENCHMARK SUMMARY RESULTS
==================================================
Metric                  | Direct Upstream | Rust mTLS Proxy
------------------------|-----------------|-----------------
Requests / Sec (RPS)    | 13184.38        | 5180.63        
p50 Latency (ms)        | 0.58            | 1.51           
p95 Latency (ms)        | 0.87            | 2.13           
p99 Latency (ms)        | 4.82            | 12.07          
Error Rate (%)          | 0.00            | 0.00           
--------------------------------------------------
Measured Proxy Overhead (p50): ~0.92 ms
==================================================
```

---

## 38. Primary Proxy Overhead Sources

1. **TLS / mTLS Cryptographic Handshake & Encryption**: RSA/ECDSA signature verification and symmetric AES-GCM encryption.
2. **X.509 SAN Identity Parsing**: Parsing DER certificate extensions to extract SPIFFE URIs.
3. **Path Normalization & Policy Matching**: Percent decoding and canonicalization.
4. **Extra Network Hop**: Additional TCP connection and context switches.

---

## 39. Docker Build & Run Instructions

Build Docker Image:
```bash
docker build -t arkion-identity-proxy .
```

Run Docker Container:
```bash
docker run -d --name arkion-proxy \
  -p 8443:8443 \
  -v $(pwd)/certs:/app/certs:ro \
  -v $(pwd)/config:/app/config:ro \
  -e ARKION_UPSTREAM_URL=http://host.docker.internal:8080 \
  arkion-identity-proxy
```

Or using Docker Compose:
```bash
docker-compose up -d
```

---

## 40. Production Considerations

- **Secrets Management**: Mount certs from Kubernetes Secrets or Vault into `/app/certs`.
- **Observability**: Export audit logs to OpenSearch / Datadog via stdout JSON stream.
- **Horizontal Scaling**: Deploy multiple proxy replicas behind a L4 Load Balancer (AWS NLB / HAProxy).

---

## 41. Presentation Dashboard UI

To facilitate local demonstration and technical evaluation without browser client-certificate prompts, a dedicated read-only HTTP presentation server is bound to `127.0.0.1:8081`:

- **Presentation Dashboard URL**: `http://127.0.0.1:8081/dashboard`
- **Dashboard API Endpoint**: `http://127.0.0.1:8081/api/dashboard-summary`
- **Secure mTLS Proxy Listener**: `https://127.0.0.1:8443`

> **Security Note**: The local presentation server on port `8081` is strictly read-only and bound only to `127.0.0.1`. It does NOT expose any administrative endpoints (such as `/admin/reload-trust`) or secrets.

---

## 42. Test Instructions

Execute all unit and integration test suites:

```bash
cargo fmt --check
cargo check
cargo test
cargo clippy -- -D warnings
```
