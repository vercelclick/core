use crate::auth::{LoginParams, login_user_bounded};
use crate::passkeys::types::LoginResponse;
use secretpass_core::{PrivateKey, PrivateKeySeed, PublicKeyEncrypt};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tsify::{Ts, Tsify};
use wasm_bindgen::JsError;
use wasm_bindgen::prelude::wasm_bindgen;

#[derive(Deserialize, Tsify)]
pub struct GenerateMachineKeyParams {
    login_params: LoginParams,
    secrets_package: HashMap<String, HashMap<String, String>>,
}

#[derive(Serialize, Tsify)]
pub struct GenerateMachineKeyResult {
    passkey_id: String,
    login_response: LoginResponse,
    id: String,
    kem_key: Option<String>,
    ecc_key: Option<String>,
    machine_key: String,
    secrets_package: HashMap<String, HashMap<String, String>>,
}

#[wasm_bindgen]
pub async fn generate_machine_key(
    params: Ts<GenerateMachineKeyParams>,
) -> Result<Ts<GenerateMachineKeyResult>, JsError> {
    let params: GenerateMachineKeyParams = params.to_rust()?;

    let (passkey, login_response, session) = login_user_bounded(&params.login_params)
        .await
        .map_err(|err| JsError::new(&format!("Error authorizing user: {}", err)))?;

    let session = session
        .ok_or_else(|| JsError::new("Secure session not attained - please report this issue"))?;

    let (machine_key, seed) = PrivateKeySeed::generate_machine_key(session.algorithm)
        .map_err(|err| JsError::new(&format!("Error generating machine key: {}", err)))?;

    let private_key = PrivateKey::from_seed(seed)
        .map_err(|err| JsError::new(&format!("Error getting private key from seed: {}", err)))?;

    let public_key = private_key.public_key();

    let mut output: HashMap<String, HashMap<String, String>> = Default::default();
    for (env, encrypted_package) in &params.secrets_package {
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
        passkey_id: passkey.id,
        login_response,
        id: public_key.machine_key_id(),
        ecc_key: public_key.ecc(),
        kem_key: public_key.kem(),
        machine_key,
        secrets_package: output,
    }
    .into_ts()?;

    Ok(result)
}
