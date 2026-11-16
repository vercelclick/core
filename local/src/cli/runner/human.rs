use crate::utils::certificates::get_certificates;
use axum::extract::State;
use axum::http::{HeaderValue, Method, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use axum_server::tls_rustls::RustlsConfig;
use click_core::constants::RP_ORIGIN;
use click_core::{KeyPair, PrivateKeySeed, TargetedPublicKey};
use serde::Serialize;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::str::FromStr;
use tokio::net::TcpListener;
use tokio::sync::mpsc;
use tokio::sync::mpsc::Sender;
use tower_http::cors::{AllowHeaders, CorsLayer};
use uuid::Uuid;

#[derive(Clone)]
struct AppState {
    tx: Sender<HashMap<String, String>>,
}

#[derive(Serialize)]
struct EncryptionDetails {
    public_key: TargetedPublicKey,
    command: Option<String>,
}

async fn get_values_from_web_async(command: Option<String>) -> HashMap<String, String> {
    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .expect("Failed to install default crypto provider");

    let (tx, mut rx) = mpsc::channel::<HashMap<String, String>>(1);

    let (_, seed) = PrivateKeySeed::generate_access_key(Uuid::now_v7());

    let private_key = KeyPair::from_seed(seed).expect("Error deriving temporary private key from seed, please raise a support ticket through support@vercel.click");
    let public_key = private_key.public_key();
    let simple_key = TargetedPublicKey {
        target: public_key.access_key_id(),
        value: public_key.encode(),
    };

    let cors_layer = CorsLayer::new()
        .allow_headers(AllowHeaders::any())
        .allow_methods([Method::GET, Method::POST, Method::OPTIONS])
        .allow_origin(RP_ORIGIN.parse::<HeaderValue>().unwrap())
        .allow_private_network(true);

    let app = Router::new()
        .route(
            "/commit",
            post(
                async move |State(state): State<AppState>,
                            Json(encrypted_secrets): Json<HashMap<String, String>>|
                            -> Response {
                    let _ = state.tx.send(encrypted_secrets).await;

                    (StatusCode::OK, "Ok").into_response()
                },
            ),
        )
        .route(
            "/details",
            get(async move || -> Response {
                let details = EncryptionDetails {
                    public_key: simple_key.clone(),
                    command: command.clone(),
                };

                (StatusCode::OK, Json(details)).into_response()
            }),
        )
        .layer(cors_layer)
        .with_state(AppState { tx });

    let addr = SocketAddr::from_str("127.0.0.1:0").expect("Invalid local socket address 127.0.0.1:0, please raise a support ticket with support@vercel.click");
    let listener = TcpListener::bind(addr).await.expect(
        "Unable to bind to an open port, this is required to decrypt secrets from the browser",
    );

    let (cert_path, key_path) = get_certificates();
    let tls_config = RustlsConfig::from_pem_file(cert_path, key_path).await
        .expect("Error parsing TLS certificate, please raise a support ticket with support@vercel.click");
    let port = listener.local_addr().unwrap().port();

    let child = tokio::spawn(
        axum_server::from_tcp_rustls(listener.into_std().unwrap(), tls_config)
            .unwrap()
            .serve(app.into_make_service())
            .into_future(),
    );

    let url = format!("{RP_ORIGIN}/?target={port}");
    eprintln!("Open {url} to decrypt secrets. Use --private-key to run directly");
    let _ = webbrowser::open(&url);

    let secrets = rx
        .recv()
        .await
        .expect("Error decrypting secrets, please retry");
    child.abort();

    private_key.decrypt_package(&secrets).unwrap()
}

pub fn get_values_from_web(command: Option<String>) -> HashMap<String, String> {
    let rt = tokio::runtime::Runtime::new().expect(
        "Error creating IO runtime, , please raise a support ticket through support@vercel.click",
    );

    rt.block_on(get_values_from_web_async(command))
}
