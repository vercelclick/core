use axum::extract::{Query, State};
use axum::response::Redirect;
use axum::routing::get;
use axum::Router;
use secretpass_api::constants::{CLOUD_RP_CONFIG, LOCAL_RP_CONFIG};
use secretpass_core::enums::{EncryptionAlgorithm, OperationMode};
use secretpass_core::{PrivateKey, PrivateKeySeed, SimpleMachinePublicKey};
use serde::Deserialize;
use std::collections::HashMap;
use tokio::sync::mpsc;
use tokio::sync::mpsc::Sender;
use uuid::Uuid;

#[derive(Clone)]
struct AppState {
    tx: Sender<HashMap<String, String>>,
}

#[derive(Deserialize)]
struct QueryParams {
    encrypted_secrets: String,
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

    let redirect_command = command.clone();
    let app = Router::new()
        .route(
            "/encrypted",
            get(
                async move |State(state): State<AppState>,
                            Query(params): Query<QueryParams>|
                            -> Redirect {
                    let encrypted_secrets: HashMap<String, String> =
                        serde_json::from_str(&params.encrypted_secrets)
                            .map_err(|err| anyhow::format_err!("Error decoding secrets: {:?}", err))
                            .unwrap();
                    let _ = state.tx.send(encrypted_secrets).await;
                    let redirect_url = if let Some(command) = redirect_command {
                        format!(
                            "{endpoint}/run/success?command={}",
                            urlencoding::encode(&command)
                        )
                    } else {
                        format!("{endpoint}/export/success")
                    };
                    Redirect::temporary(&redirect_url)
                },
            ),
        )
        .with_state(AppState { tx });

    let listener = tokio::net::TcpListener::bind("localhost:0").await.expect(
        "Unable to bind to an open port, this is required to decrypt secrets from the browser",
    );

    let port = listener.local_addr().unwrap().port();

    let simple_key = SimpleMachinePublicKey {
        id: public_key.machine_key_id(),
        ecc: public_key.ecc(),
        kem: public_key.kem(),
    };
    let simple_key =
        serde_json::to_string(&simple_key).expect("Error encoding temporary public key, please raise a support ticket through support@secretpass.cloud");
    let url = if let Some(command) = command {
        format!(
            "{endpoint}/run/{port}?command={}&public_key={}",
            urlencoding::encode(&command),
            urlencoding::encode(&simple_key)
        )
    } else {
        format!(
            "{endpoint}/export/{port}?public_key={}",
            urlencoding::encode(&simple_key)
        )
    };

    let child = tokio::spawn(axum::serve(listener, app).into_future());

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
