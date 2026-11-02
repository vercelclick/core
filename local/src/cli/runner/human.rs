use axum::extract::State;
use axum::http::{HeaderValue, Method, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use secretpass_api::constants::{CLOUD_RP_CONFIG, LOCAL_RP_CONFIG};
use secretpass_core::enums::{EncryptionAlgorithm, OperationMode};
use secretpass_core::{PrivateKey, PrivateKeySeed, SimpleMachinePublicKey};
use serde::Serialize;
use std::collections::HashMap;
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
    public_key: SimpleMachinePublicKey,
    command: Option<String>,
}

async fn get_values_from_web_async(
    mode: OperationMode,
    command: Option<String>,
) -> (PrivateKey, HashMap<String, String>) {
    let endpoint = match mode {
        OperationMode::Local => LOCAL_RP_CONFIG.origin,
        OperationMode::Cloud => CLOUD_RP_CONFIG.origin,
    };

    let (tx, mut rx) = mpsc::channel::<HashMap<String, String>>(1);

    let (_, seed) = PrivateKeySeed::generate_machine_key(Uuid::now_v7()).expect("Error generating temporary private key, please raise a support ticket through support@secretpass.cloud");

    let private_key = PrivateKey::from_seed(seed).expect("Error deriving temporary private key from seed, please raise a support ticket through support@secretpass.cloud");
    let public_key = private_key.public_key(EncryptionAlgorithm::ECC);
    let simple_key = SimpleMachinePublicKey {
        id: public_key.machine_key_id(),
        ecc: public_key.ecc(),
        kem: public_key.kem(),
    };

    let cors_layer = CorsLayer::new()
        .allow_headers(AllowHeaders::any())
        .allow_methods([Method::GET, Method::POST, Method::OPTIONS])
        .allow_origin(endpoint.parse::<HeaderValue>().unwrap())
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

    let listener = tokio::net::TcpListener::bind("localhost:0").await.expect(
        "Unable to bind to an open port, this is required to decrypt secrets from the browser",
    );

    let port = listener.local_addr().unwrap().port();

    let child = tokio::spawn(axum::serve(listener, app).into_future());

    let url = format!("{endpoint}/?target={port}");
    eprintln!("Open {url} to decrypt secrets. Use --private-key to run directly");
    let _ = webbrowser::open(&url);

    let secrets = rx
        .recv()
        .await
        .expect("Error decrypting secrets, please retry");
    child.abort();

    (private_key, secrets)
}

pub fn get_values_from_web(
    mode: OperationMode,
    command: Option<String>,
) -> (PrivateKey, HashMap<String, String>) {
    let rt = tokio::runtime::Runtime::new().expect("Error creating IO runtime, , please raise a support ticket through support@secretpass.cloud");

    rt.block_on(get_values_from_web_async(mode, command))
}
