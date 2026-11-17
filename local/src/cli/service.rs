use crate::backend::LocalBackendProvider;
use crate::config::{CONFIG_DIR, DATA_DIR};
use crate::utils::certificates::get_certificates;
use axum_server::tls_rustls::RustlsConfig;
use click_api::backend::ApiStateInner;
use click_api::build_api_router;
use click_core::constants::{APP_SLUG, RP_ORIGIN};
use daemon_kit::{Daemon, DaemonConfig};
use std::fs;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::runtime::Runtime;

#[cfg(not(debug_assertions))]
const PORT: u16 = 20206;

#[cfg(debug_assertions)]
const PORT: u16 = 20207;

async fn run_server(cert_path: PathBuf, key_path: PathBuf) {
    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .expect("Failed to install default crypto provider");

    let backend = LocalBackendProvider::default();

    let state = ApiStateInner::new(Arc::new(backend));

    let app = build_api_router(state, None, None);

    let addr = SocketAddr::from_str(&format!("127.0.0.1:{}", PORT)).unwrap();

    let bind_error = format!(
        "Unable to bind to {APP_SLUG}.localhost:{PORT}, check if another service is using the port or the vault service is already running"
    );
    let listener = TcpListener::bind(addr).await.expect(&bind_error);

    let tls_config = RustlsConfig::from_pem_file(cert_path, key_path).await
        .expect("Error parsing TLS certificate, please raise a support ticket with support@vercel.click");

    eprintln!("Starting click vault local service listening: https://{APP_SLUG}.localhost:{PORT}");
    axum_server::from_tcp_rustls(listener.into_std().unwrap(), tls_config)
        .unwrap()
        .serve(app.into_make_service())
        .await
        .unwrap();
}

pub fn build_daemon() -> Daemon {
    if !CONFIG_DIR.exists() {
        fs::create_dir_all(CONFIG_DIR.clone()).expect("Error creating config directory");
    }

    if !DATA_DIR.exists() {
        fs::create_dir_all(DATA_DIR.clone()).expect("Error creating config directory");
    }
    let config = DaemonConfig::new("click-vault-local-service")
        .pid_dir(CONFIG_DIR.clone())
        .log_file(DATA_DIR.join("service.log"))
        .description(env!("CARGO_PKG_DESCRIPTION"));

    Daemon::new(config)
}

pub fn start_service_command(foreground: bool, silent: bool) {
    let daemon = build_daemon();

    if let Some(pid) = daemon.running_pid() {
        if !silent {
            eprintln!(
                "Click Vault Service already active({pid}) -> https://{APP_SLUG}.localhost:{PORT}"
            );
            eprintln!("You can manage secrets through {RP_ORIGIN}");
        } else {
            let _ = webbrowser::open(RP_ORIGIN);
        }
        return;
    }

    eprintln!("Starting Click Vault Local service in the background");
    eprintln!("You can manage secrets through {RP_ORIGIN}");

    let (cert_path, key_path) = get_certificates();

    daemon
        .start(foreground, || {
            // We're now in a background process
            let rt = Runtime::new().expect("Failed to create Tokio runtime");

            rt.block_on(async {
                run_server(cert_path, key_path).await;
            });

            Ok(())
        })
        .expect("Error starting click vault local service");
}

pub fn stop_service_command() {
    let daemon = build_daemon();

    if daemon.is_running() {
        eprintln!("Stopping Click vault local service");
        daemon.stop().unwrap();
    } else {
        eprintln!("Click vault local service is not active")
    }
}

pub fn check_status_command() {
    let daemon = build_daemon();

    if let Some(pid) = daemon.running_pid() {
        println!(
            "🟢 Click Vault Local Service is active({pid}) -> https://{APP_SLUG}.localhost:{PORT}"
        )
    } else {
        println!("Click Vault Local Service is not active")
    }
}
