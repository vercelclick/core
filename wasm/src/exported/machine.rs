use crate::auth::DecryptionAuthorizationRequest;
use secretpass_core::enums::EncryptionAlgorithm;
use secretpass_core::passkeys::authorize::PasskeyAuthorizationResult;
use secretpass_core::{PrivateKey, PrivateKeySeed, PublicKeyEncrypt};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tsify::{Ts, Tsify};
use uuid::Uuid;
use wasm_bindgen::JsError;
use wasm_bindgen::prelude::wasm_bindgen;

#[derive(Deserialize, Tsify)]
pub struct GenerateMachineKeyRequest {
    project_id: Uuid,
    algorithm: EncryptionAlgorithm,
    auth_request: DecryptionAuthorizationRequest,
    secrets_package: HashMap<String, HashMap<String, String>>,
}

#[derive(Serialize, Tsify)]
pub struct GenerateMachineKeyResult {
    auth_response: PasskeyAuthorizationResult,
    id: String,
    kem_key: Option<String>,
    ecc_key: Option<String>,
    machine_key: String,
    secrets_package: HashMap<String, HashMap<String, String>>,
}

#[wasm_bindgen]
pub async fn generate_machine_key(
    ts_request: Ts<GenerateMachineKeyRequest>,
) -> Result<Ts<GenerateMachineKeyResult>, JsError> {
    let request: GenerateMachineKeyRequest = ts_request.to_rust()?;

    let (auth_response, session) = request
        .auth_request
        .authorize()
        .await
        .map_err(|err| JsError::new(&format!("Error authorizing user: {}", err)))?;

    let (machine_key, seed) = PrivateKeySeed::generate_machine_key(request.project_id)
        .map_err(|err| JsError::new(&format!("Error generating machine key: {}", err)))?;

    let private_key = PrivateKey::from_seed(seed)
        .map_err(|err| JsError::new(&format!("Error getting private key from seed: {}", err)))?;

    let public_key = private_key.public_key(request.algorithm);

    let mut output: HashMap<String, HashMap<String, String>> = Default::default();
    for (env, encrypted_package) in &request.secrets_package {
        let decrypted_package = session.decrypt_package(encrypted_package).map_err(|err| {
            JsError::new(&format!("Error decrypting secrets from {}: {}", env, err))
        })?;

        let encrypted_package = public_key
            .encrypt_package(decrypted_package)
            .map_err(|err| {
                JsError::new(&format!("Error encrypting secrets for {}: {}", env, err))
            })?;
        output.insert(env.clone(), encrypted_package);
    }

    let result = GenerateMachineKeyResult {
        auth_response,
        id: public_key.machine_key_id(),
        ecc_key: public_key.ecc(),
        kem_key: public_key.kem(),
        machine_key,
        secrets_package: output,
    }
    .into_ts()?;

    Ok(result)
}
