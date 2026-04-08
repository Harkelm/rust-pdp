use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use axum::routing::{get, post};
use axum::Router;
use tracing_subscriber::EnvFilter;

use cedar_pdp::handlers;
use cedar_pdp::policy::PolicyStore;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env().add_directive("cedar_pdp=info".parse()?))
        .init();

    let policy_dir = std::env::var("CEDAR_POLICY_DIR").unwrap_or_else(|_| "policies".to_string());
    let policy_path = PathBuf::from(&policy_dir);

    if !policy_path.exists() {
        return Err(format!("policy directory does not exist: {}", policy_path.display()).into());
    }

    let store = PolicyStore::from_dir(&policy_path)?;
    tracing::info!(
        policies = store.policy_count(),
        dir = %policy_path.display(),
        "loaded Cedar policies"
    );

    let state: handlers::AppState = Arc::new(store);

    let app = Router::new()
        .route("/v1/is_authorized", post(handlers::is_authorized))
        .route("/health", get(handlers::health))
        .with_state(state);

    let addr = SocketAddr::from(([0, 0, 0, 0], 8180));
    tracing::info!(%addr, "starting Cedar PDP");

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}
