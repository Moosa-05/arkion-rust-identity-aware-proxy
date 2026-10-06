use arkion_identity_proxy::{AppConfig, ProxyError, ProxyServer};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

#[tokio::main]
async fn main() -> Result<(), ProxyError> {
    let env_filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("info,arkion_identity_proxy=debug"));

    tracing_subscriber::registry()
        .with(env_filter)
        .with(tracing_subscriber::fmt::layer().with_target(true))
        .init();

    tracing::info!("Starting Arkion Identity-Aware mTLS Reverse Proxy (Phase 2)...");

    let config = AppConfig::load()?;
    let server = ProxyServer::new(config)?;

    server.run().await
}
