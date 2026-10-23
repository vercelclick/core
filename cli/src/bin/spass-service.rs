use daemonize::Daemonize;
use secretpass_api::{ApiState, create_backend_app};
use secretpass_cli::backend::LocalBackendProvider;
use secretpass_cli::config::{CONFIG_DIR, DATA_DIR, HOME_DIR};
use secretpass_core::enums::OperationMode;
use std::fs;
use std::fs::OpenOptions;
use std::sync::Arc;
use tokio::runtime::Runtime;

const API_HOST: &str = env!("API_HOST");

async fn run_server() {
    let backend = LocalBackendProvider::new(true);

    let state = ApiState {
        mode: OperationMode::Local,
        backend: Arc::new(backend),
    };

    let app = create_backend_app().with_state(state);

    let listener = tokio::net::TcpListener::bind(API_HOST)
        .await
        .expect("Unable to bind to secretpass.localhost:20206, check if another instance of secretpass is already running");

    println!("Secretpass local service running under: {API_HOST}");

    axum::serve(listener, app).await.unwrap();
}

#[tokio::main]
async fn main() {
    if cfg!(debug_assertions) {
        run_server().await;
    }

    if !CONFIG_DIR.is_dir() {
        fs::create_dir_all(CONFIG_DIR.clone()).expect("Error creating config directory");
    }

    if !DATA_DIR.is_dir() {
        fs::create_dir_all(DATA_DIR.clone()).expect("Error creating config directory");
    }

    let working_dir = format!("{}", HOME_DIR.display());
    let pid_file = format!("{}", CONFIG_DIR.join(".process").display());

    let stdout = OpenOptions::new()
        .create(true)
        .truncate(true)
        .open(DATA_DIR.join("stdout.log"))
        .unwrap();
    let stderr = OpenOptions::new()
        .create(true)
        .truncate(true)
        .open(DATA_DIR.join("stderr.log"))
        .unwrap();

    let daemon = Daemonize::new()
        .pid_file(&pid_file)
        .working_directory(&working_dir)
        .stdout(stdout)
        .stderr(stderr);

    match daemon.start() {
        Ok(_) => {
            // We're now in a background process
            let rt = Runtime::new().expect("Failed to create Tokio runtime");

            rt.block_on(async {
                run_server().await;
            });
        }
        Err(e) => {
            eprintln!("Error starting secretpass daemon: {}", e);
            std::process::exit(1);
        }
    }
}
