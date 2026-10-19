use crate::auth::{LoginParams, login_user_bounded};
use crate::passkeys::types::LoginResponse;
use secretpass_core::{
    PublicKeyEncrypt, SecretpassProjectMachinePublicKey, SecretpassProjectUserPublicKey,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tsify::{Ts, Tsify};
use wasm_bindgen::JsError;
use wasm_bindgen::prelude::wasm_bindgen;

#[derive(Deserialize, Tsify)]
pub struct EncryptSecretParams {
    login_params: LoginParams,
    user_keys: Vec<SecretpassProjectUserPublicKey>,
    machine_keys: Vec<SecretpassProjectMachinePublicKey>,
    secret_value: String,
}

#[derive(Serialize, Tsify)]
pub struct EncryptSecretResult {
    passkey_id: String,
    login_response: LoginResponse,
    user_values: HashMap<String, String>,
    machine_values: HashMap<String, String>,
}

#[wasm_bindgen]
pub async fn encrypt_secret(
    params: Ts<EncryptSecretParams>,
) -> Result<Ts<EncryptSecretResult>, JsError> {
    let params: EncryptSecretParams = params.to_rust()?;

    let (passkey, login_response, _) = login_user_bounded(&params.login_params)
        .await
        .map_err(|err| JsError::new(&format!("Error authorizing user: {}", err)))?;

    let mut user_values: HashMap<String, String> = HashMap::new();
    for pk in params.user_keys {
        let key_id = pk.id.clone();
        let encrypted_value = pk
            .encrypt(params.secret_value.clone().into_bytes())
            .map_err(|err| JsError::new(&format!("Error encrypting secret: {}", err)))?;
        user_values.insert(key_id, encrypted_value);
    }

    let mut machine_values: HashMap<String, String> = HashMap::new();
    for pk in params.machine_keys {
        let key_id = pk.id.clone();
        let encrypted_value = pk
            .encrypt(params.secret_value.clone().into_bytes())
            .map_err(|err| JsError::new(&format!("Error encrypting secret: {}", err)))?;
        machine_values.insert(key_id, encrypted_value);
    }

    let result = EncryptSecretResult {
        passkey_id: passkey.id,
        login_response,
        user_values,
        machine_values,
    }
    .into_ts()?;

    Ok(result)
}

#[derive(Deserialize, Tsify)]
pub struct DecryptSecretParams {
    login_params: LoginParams,
    encrypted_secret: String,
}

#[wasm_bindgen]
pub async fn decrypt_secret(params: Ts<DecryptSecretParams>) -> Result<String, JsError> {
    let params: DecryptSecretParams = params.to_rust()?;

    let (_, _, session) = login_user_bounded(&params.login_params)
        .await
        .map_err(|err| JsError::new(&format!("Error authorizing user: {}", err)))?;

    let plain_value = session
        .ok_or_else(|| JsError::new("Secure session not attained - please report this issue"))?
        .decrypt(&params.encrypted_secret)
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
pub struct ReEncryptPackageParams {
    login_params: LoginParams,
    target_key: TargetKey,
    secrets_package: HashMap<String, HashMap<String, HashMap<String, String>>>,
}

#[derive(Serialize, Tsify)]
pub struct ReEncryptPackageResult {
    passkey_id: String,
    login_response: LoginResponse,
    secrets_package: HashMap<String, HashMap<String, HashMap<String, String>>>,
}

#[wasm_bindgen]
pub async fn reencrypt_package(
    params: Ts<ReEncryptPackageParams>,
) -> Result<Ts<ReEncryptPackageResult>, JsError> {
    let params: ReEncryptPackageParams = params.to_rust()?;

    let (passkey, login_response, session) = login_user_bounded(&params.login_params)
        .await
        .map_err(|err| JsError::new(&format!("Error authorizing user: {}", err)))?;

    let session = session
        .ok_or_else(|| JsError::new("Secure session not attained - please report this issue"))?;

    let mut output: HashMap<String, HashMap<String, HashMap<String, String>>> = Default::default();
    for (workspace, workspace_package) in &params.secrets_package {
        let mut workspace_output: HashMap<String, HashMap<String, String>> = HashMap::new();

        for (env, encrypted_package) in workspace_package {
            let decrypted_package = session.decrypt_package(encrypted_package).map_err(|err| {
                JsError::new(&format!("Error decrypting secrets from {}: {}", env, err))
            })?;

            let encrypted_package = match &params.target_key {
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
        passkey_id: passkey.id,
        login_response,
        secrets_package: output,
    }
    .into_ts()?;

    Ok(result)
}

#[derive(Deserialize, Tsify)]
pub struct DecryptEnvPackageParams {
    login_params: LoginParams,
    secrets_package: HashMap<String, String>,
}

#[derive(Serialize, Tsify)]
pub struct DecryptEnvPackageResult {
    passkey_id: String,
    login_response: LoginResponse,
    secrets_package: HashMap<String, String>,
}

#[wasm_bindgen]
pub async fn decrypt_env_package(
    params: Ts<DecryptEnvPackageParams>,
) -> Result<Ts<DecryptEnvPackageResult>, JsError> {
    let params: DecryptEnvPackageParams = params.to_rust()?;

    let (passkey, login_response, session) = login_user_bounded(&params.login_params)
        .await
        .map_err(|err| JsError::new(&format!("Error authorizing user: {}", err)))?;

    let mut output: HashMap<String, String> = Default::default();
    let decrypted_package = session
        .ok_or_else(|| JsError::new("Secure session not attained - please report this issue"))?
        .decrypt_package(&params.secrets_package)
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
        passkey_id: passkey.id,
        login_response,
        secrets_package: output,
    }
    .into_ts()?;

    Ok(result)
}
