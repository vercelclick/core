use crate::backend::LocalBackendProvider;
use crate::config::{CONFIG_DIR, DATA_DIR};
use crate::utils::certificates::get_certificates;
use axum_server::tls_rustls::RustlsConfig;
use daemon_kit::{Daemon, DaemonConfig};
use secretpass_api::{ApiStateInner, create_backend_app};
use secretpass_core::enums::OperationMode;
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

    let state = ApiStateInner {
        mode: OperationMode::Local,
        backend: Arc::new(backend),
    };

    let app = create_backend_app(state);
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 20206);
    let listener = TcpListener::bind(addr).await
        .expect("Unable to bind to secretpass.localhost:20206, check if another instance of secretpass is already running");
    let (cert_path, key_path) = get_certificates();
    let tls_config = RustlsConfig::from_pem_file(cert_path, key_path).await
        .expect("Error parsing TLS certificate, please raise a support ticket with support@secretpass.cloud");

    eprintln!("Starting secretpass local service listening: https://localhost:20206");
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
    let config = DaemonConfig::new("secretpass-local-service")
        .pid_dir(CONFIG_DIR.clone())
        .log_file(DATA_DIR.join("service.log"))
        .description(env!("CARGO_PKG_DESCRIPTION"));

    Daemon::new(config)
}

pub fn start_service_command(foreground: bool, silent: bool) {
    let daemon = build_daemon();

    if let Some(pid) = daemon.running_pid() {
        if !silent {
            eprintln!("Secretpass Service already active({pid}) -> https://localhost:20206");
            eprintln!("You can manage secrets through https:://local.secretpass.cloud");
        } else {
            let _ = webbrowser::open("https://local.secretpass.cloud");
        }
        return;
    }

    eprintln!("Starting Secretpass service in the background");
    eprintln!("You can manage secrets through https:://local.secretpass.cloud");

    daemon
        .start(foreground, || {
            // We're now in a background process
            let rt = Runtime::new().expect("Failed to create Tokio runtime");

            rt.block_on(async {
                run_server().await;
            });

            Ok(())
        })
        .expect("Error starting secretpass service");
}

pub fn stop_service_command() {
    let daemon = build_daemon();

    if daemon.is_running() {
        eprintln!("Stopping Secretpass service");
        daemon.stop().unwrap();
    } else {
        eprintln!("Secretpass service is not active")
    }
}

pub fn check_status_command() {
    let daemon = build_daemon();

    if let Some(pid) = daemon.running_pid() {
        println!("🟢 Secretpass Service is active({pid}) -> https://localhost:20206")
    } else {
        println!("Secretpass service is not active")
    }
}
