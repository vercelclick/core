use crate::backend::LocalBackendProvider;
use crate::config::{CONFIG_DIR, DATA_DIR};
use crate::utils::certificates::get_certificates;
use axum_server::tls_rustls::RustlsConfig;
use click_api::backend::ApiStateInner;
use click_api::build_api_router;
use daemon_kit::{Daemon, DaemonConfig};
use std::fs;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::runtime::Runtime;

async fn run_server() {
    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .expect("Failed to install default crypto provider");

    let backend = LocalBackendProvider::default();

    let state = ApiStateInner::new(Arc::new(backend));

    let app = build_api_router(state, None, None);
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 20206);
    let listener = TcpListener::bind(addr).await
        .expect("Unable to bind to localhost:20206, check if another service is using the port or the vault service is already running");
    let (cert_path, key_path) = get_certificates();
    let tls_config = RustlsConfig::from_pem_file(cert_path, key_path).await
        .expect("Error parsing TLS certificate, please raise a support ticket with support@vercel.click");

    eprintln!("Starting click vault local service listening: https://localhost:20206");
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
            eprintln!("Click Vault Service already active({pid}) -> https://localhost:20206");
            eprintln!("You can manage secrets through https:://vault.vercel.click");
        } else {
            let _ = webbrowser::open("https://vault.vercel.click");
        }
        return;
    }

    eprintln!("Starting Click Vault Local service in the background");
    eprintln!("You can manage secrets through https:://vault.vercel.click");

    daemon
        .start(foreground, || {
            // We're now in a background process
            let rt = Runtime::new().expect("Failed to create Tokio runtime");

            rt.block_on(async {
                run_server().await;
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
        println!("🟢 Click Vault Local Service is active({pid}) -> https://localhost:20206")
    } else {
        println!("Click Vault Local Service is not active")
    }
}
