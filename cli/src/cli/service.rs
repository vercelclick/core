use crate::backend::LocalBackendProvider;
use crate::config::{CONFIG_DIR, DATA_DIR};
use daemon_kit::{Daemon, DaemonConfig};
use secretpass_api::{ApiStateInner, create_backend_app};
use secretpass_core::enums::OperationMode;
use std::fs;
use std::sync::Arc;
use tokio::runtime::Runtime;

const API_HOST: &str = env!("API_HOST");

async fn run_server() {
    let backend = LocalBackendProvider::default();

    let state = ApiStateInner {
        mode: OperationMode::Local,
        backend: Arc::new(backend),
    };

    let app = create_backend_app(state);

    let listener = tokio::net::TcpListener::bind(API_HOST)
        .await
        .expect("Unable to bind to secretpass.localhost:20206, check if another instance of secretpass is already running");

    println!("Secretpass local service running under: {API_HOST}");

    axum::serve(listener, app).await.unwrap();
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

pub fn start_service_command(silent: bool) {
    let daemon = build_daemon();

    if let Some(pid) = daemon.running_pid() {
        if !silent {
            eprintln!("Secretpass Service already active({pid}) -> http://localhost:20206");
            eprintln!("You can manage secrets through https:://local.secretpass.cloud");
        } else {
            let _ = webbrowser::open("https://local.secretpass.cloud");
        }
        return;
    }

    eprintln!("Starting Secretpass service in the background");
    eprintln!("You can manage secrets through https:://local.secretpass.cloud");

    daemon
        .start(cfg!(debug_assertions), || {
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
        println!("🟢 Secretpass Service is active({pid}) -> http://localhost:20206")
    } else {
        println!("Secretpass service is not active")
    }
}
