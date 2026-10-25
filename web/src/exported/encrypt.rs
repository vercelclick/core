use crate::auth::{AuthorizationRequest, DecryptionAuthorizationRequest};
use crate::passkeys::authorize::PasskeyAuthorizationResponse;
use secretpass_core::{
    PublicKeyEncrypt, SecretpassProjectMachinePublicKey, SecretpassProjectUserPublicKey,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tsify::{Ts, Tsify};
use wasm_bindgen::JsError;
use wasm_bindgen::prelude::wasm_bindgen;

#[derive(Deserialize, Tsify)]
pub struct EncryptSecretRequest {
    auth_request: AuthorizationRequest,
    user_keys: Vec<SecretpassProjectUserPublicKey>,
    machine_keys: Vec<SecretpassProjectMachinePublicKey>,
    secret_value: String,
}

#[derive(Serialize, Tsify)]
pub struct EncryptSecretResult {
    auth_response: PasskeyAuthorizationResponse,
    user_values: HashMap<String, String>,
    machine_values: HashMap<String, String>,
}

#[wasm_bindgen]
pub async fn encrypt_secret(
    ts_request: Ts<EncryptSecretRequest>,
) -> Result<Ts<EncryptSecretResult>, JsError> {
    let request: EncryptSecretRequest = ts_request.to_rust()?;

    let auth_response = request
        .auth_request
        .authorize()
        .await
        .map_err(|err| JsError::new(&format!("Error authorizing user: {}", err)))?;

    let mut user_values: HashMap<String, String> = HashMap::new();
    for pk in request.user_keys {
        let key_id = pk.id.clone();
        let encrypted_value = pk
            .encrypt(request.secret_value.clone().into_bytes())
            .map_err(|err| JsError::new(&format!("Error encrypting secret: {}", err)))?;
        user_values.insert(key_id, encrypted_value);
    }

    let mut machine_values: HashMap<String, String> = HashMap::new();
    for pk in request.machine_keys {
        let key_id = pk.id.clone();
        let encrypted_value = pk
            .encrypt(request.secret_value.clone().into_bytes())
            .map_err(|err| JsError::new(&format!("Error encrypting secret: {}", err)))?;
        machine_values.insert(key_id, encrypted_value);
    }

    let result = EncryptSecretResult {
        auth_response,
        user_values,
        machine_values,
    }
    .into_ts()?;

    Ok(result)
}

#[derive(Deserialize, Tsify)]
pub struct DecryptSecretRequest {
    auth_request: DecryptionAuthorizationRequest,
    encrypted_secret: String,
}

#[wasm_bindgen]
pub async fn decrypt_secret(ts_request: Ts<DecryptSecretRequest>) -> Result<String, JsError> {
    let request: DecryptSecretRequest = ts_request.to_rust()?;

    let (_, session) = request
        .auth_request
        .authorize()
        .await
        .map_err(|err| JsError::new(&format!("Error authorizing user: {}", err)))?;

    let plain_value = session
        .decrypt(&request.encrypted_secret)
        .map_err(|err| JsError::new(&format!("Error decrypting secret: {}", err)))?;

    String::from_utf8(plain_value)
        .map_err(|err| JsError::new(&format!("Error decoding decrypted secret: {}", err)))
}

#[derive(Deserialize, Tsify)]
enum TargetKey {
    User(SecretpassProjectUserPublicKey),
    Machine(SecretpassProjectMachinePublicKey),
}

#[derive(Deserialize, Tsify)]
pub struct ReEncryptPackageRequest {
    auth_request: DecryptionAuthorizationRequest,
    target_key: TargetKey,
    secrets_package: HashMap<String, HashMap<String, HashMap<String, String>>>,
}

#[derive(Serialize, Tsify)]
pub struct ReEncryptPackageResult {
    auth_response: PasskeyAuthorizationResponse,
    secrets_package: HashMap<String, HashMap<String, HashMap<String, String>>>,
}

#[wasm_bindgen]
pub async fn reencrypt_package(
    ts_request: Ts<ReEncryptPackageRequest>,
) -> Result<Ts<ReEncryptPackageResult>, JsError> {
    let request: ReEncryptPackageRequest = ts_request.to_rust()?;

    let (auth_response, session) = request
        .auth_request
        .authorize()
        .await
        .map_err(|err| JsError::new(&format!("Error authorizing user: {}", err)))?;

    let mut output: HashMap<String, HashMap<String, HashMap<String, String>>> = Default::default();
    for (workspace, workspace_package) in &request.secrets_package {
        let mut workspace_output: HashMap<String, HashMap<String, String>> = HashMap::new();

        for (env, encrypted_package) in workspace_package {
            let decrypted_package = session.decrypt_package(encrypted_package).map_err(|err| {
                JsError::new(&format!("Error decrypting secrets from {}: {}", env, err))
            })?;

            let encrypted_package = match &request.target_key {
                TargetKey::User(user_key) => user_key.encrypt_package(decrypted_package),
                TargetKey::Machine(machine_key) => machine_key.encrypt_package(decrypted_package),
            }
            .map_err(|err| {
                JsError::new(&format!("Error encrypting secrets for {}: {}", env, err))
            })?;
            workspace_output.insert(env.clone(), encrypted_package);
        }
        output.insert(workspace.clone(), workspace_output);
    }

    let result = ReEncryptPackageResult {
        auth_response,
        secrets_package: output,
    }
    .into_ts()?;

    Ok(result)
}

#[derive(Deserialize, Tsify)]
pub struct DecryptEnvPackageRequest {
    auth_request: DecryptionAuthorizationRequest,
    secrets_package: HashMap<String, String>,
}

#[derive(Serialize, Tsify)]
pub struct DecryptEnvPackageResult {
    auth_response: PasskeyAuthorizationResponse,
    secrets_package: HashMap<String, String>,
}

#[wasm_bindgen]
pub async fn decrypt_env_package(
    request: Ts<DecryptEnvPackageRequest>,
) -> Result<Ts<DecryptEnvPackageResult>, JsError> {
    let request: DecryptEnvPackageRequest = request.to_rust()?;

    let (auth_response, session) = request
        .auth_request
        .authorize()
        .await
        .map_err(|err| JsError::new(&format!("Error authorizing user: {}", err)))?;

    let mut output: HashMap<String, String> = Default::default();
    let decrypted_package = session
        .decrypt_package(&request.secrets_package)
        .map_err(|err| JsError::new(&format!("Error decrypting secrets: {}", err)))?;
    for (env, decrypted_secret) in decrypted_package {
        output.insert(
            env.clone(),
            String::from_utf8(decrypted_secret).map_err(|err| {
                JsError::new(&format!(
                    "Error converting decrypted secret to string: {}",
                    err
                ))
            })?,
        );
    }

    let result = DecryptEnvPackageResult {
        auth_response,
        secrets_package: output,
    }
    .into_ts()?;

    Ok(result)
}
