use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use axum::middleware;
use axum::routing::{get, post};
use axum::Router;
use notify::event::ModifyKind;
use notify::{Event, EventKind, RecursiveMode, Watcher};
use tracing_subscriber::EnvFilter;

use cedar_pdp::handlers::{self, AppContext};
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

    let port: u16 = std::env::var("PDP_PORT")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(8180);

    let admin_token = std::env::var("PDP_ADMIN_TOKEN").ok();
    if admin_token.is_none() {
        tracing::warn!(
            "PDP_ADMIN_TOKEN not set -- admin endpoints are unrestricted (dev mode). \
             Set PDP_ADMIN_TOKEN to require Bearer authentication on /admin/* routes."
        );
    }

    let store = PolicyStore::from_dir(&policy_path)?;
    tracing::info!(
        policies = store.policy_count(),
        dir = %policy_path.display(),
        "loaded Cedar policies"
    );

    let ctx = Arc::new(AppContext::new(store, admin_token));

    let app = Router::new()
        .route("/v1/is_authorized", post(handlers::is_authorized))
        .route("/v1/batch_is_authorized", post(handlers::batch_is_authorized))
        .route("/v1/policy-info", get(handlers::policy_info))
        .route("/admin/reload", post(handlers::admin_reload))
        .route("/healthz", get(handlers::healthz))
        .route("/readyz", get(handlers::readyz))
        .route("/health", get(handlers::health))
        .layer(middleware::from_fn(handlers::request_id_layer))
        .with_state(ctx.clone());

    // Start file watcher AFTER building router but BEFORE serving.
    // The returned watcher must be kept alive for the lifetime of the program.
    let _watcher = start_file_watcher(ctx)?;

    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    tracing::info!(%addr, "starting Cedar PDP");

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;

    tracing::info!("shutdown complete");
    Ok(())
}

/// Wait for SIGINT (ctrl-c) or SIGTERM, then return to trigger graceful drain.
async fn shutdown_signal() {
    let ctrl_c = tokio::signal::ctrl_c();

    #[cfg(unix)]
    let terminate = async {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("failed to install SIGTERM handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => { tracing::info!("received SIGINT, starting graceful shutdown"); }
        _ = terminate => { tracing::info!("received SIGTERM, starting graceful shutdown"); }
    }
}

/// Spawn a file watcher that automatically reloads policies when .cedar or
/// .cedarschema files change. Returns the watcher handle -- caller must keep
/// it alive (do not drop it) for the watcher to remain active.
fn start_file_watcher(
    ctx: handlers::AppState,
) -> Result<notify::RecommendedWatcher, Box<dyn std::error::Error>> {
    let policy_dir = ctx.policy_dir().to_path_buf();

    let mut watcher = notify::recommended_watcher(move |res: Result<Event, notify::Error>| {
        match res {
            Ok(event) => {
                // Ignore events that don't touch .cedar or .cedarschema files.
                let is_policy_file = event.paths.iter().any(|p| {
                    p.extension()
                        .map(|e| e == "cedar" || e == "cedarschema")
                        .unwrap_or(false)
                });
                if !is_policy_file {
                    return;
                }

                // Only react to modifications, creations, and removals.
                let is_relevant = matches!(
                    event.kind,
                    EventKind::Create(_)
                        | EventKind::Remove(_)
                        | EventKind::Modify(ModifyKind::Data(_))
                        | EventKind::Modify(ModifyKind::Name(_))
                        | EventKind::Modify(ModifyKind::Any)
                        | EventKind::Modify(ModifyKind::Other)
                );
                if !is_relevant {
                    return;
                }

                let old_count = ctx.policy_count();
                match ctx.reload() {
                    Ok(new_count) => {
                        tracing::info!(old_count, new_count, "policy reload successful");
                    }
                    Err(e) => {
                        tracing::warn!(
                            error = %e,
                            "policy reload failed, keeping previous policy set"
                        );
                    }
                }
            }
            Err(e) => {
                tracing::error!(error = %e, "file watcher error");
            }
        }
    })?;

    watcher.watch(&policy_dir, RecursiveMode::NonRecursive)?;
    tracing::info!(dir = %policy_dir.display(), "file watcher started");

    Ok(watcher)
}
