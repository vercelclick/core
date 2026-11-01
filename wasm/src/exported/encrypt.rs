use crate::auth::{AuthorizationRequest, DecryptionAuthorizationRequest};
use secretpass_core::enums::SecretDataType;
use secretpass_core::passkeys::authorize::PasskeyAuthorizationResult;
use secretpass_core::{
    ContributorPublicKey, ContributorSecretValue, ContributorUpdateValue, MachineUpdateValue,
    PublicKeyEncrypt, SimpleContributorPublicKey, SimpleMachinePublicKey,
};
use serde::{Deserialize, Serialize};
use ts_rs::TS;
use tsify::{Ts, Tsify};
use wasm_bindgen::JsError;
use wasm_bindgen::prelude::wasm_bindgen;

#[derive(Deserialize, Tsify)]
pub struct EncryptSecretRequest {
    pub auth_request: AuthorizationRequest,
    pub machines_keys: Vec<SimpleMachinePublicKey>,
    pub contributors_keys: Vec<SimpleContributorPublicKey>,
    pub name: String,
    pub env_name: String,
    pub tag_name: String,
    pub secret_value: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Tsify, TS)]
pub struct EncryptSecretResult {
    pub auth_response: PasskeyAuthorizationResult,
    pub machines_values: Vec<MachineUpdateValue>,
    pub contributors_values: Vec<ContributorUpdateValue>,
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

    let mut contributors_values: Vec<ContributorUpdateValue> = Vec::new();
    for pk in request.contributors_keys {
        let encrypted_value = pk
            .encrypt(request.secret_value.clone())
            .map_err(|err| JsError::new(&format!("Error encrypting secret: {}", err)))?;
        contributors_values.push(ContributorUpdateValue {
            target: pk.id,
            encrypted_value,
            data_type: SecretDataType::Text,
            name: request.name.clone(),
            environment: request.env_name.clone(),
            tag: request.tag_name.clone(),
        });
    }

    let mut machines_values: Vec<MachineUpdateValue> = Vec::new();
    for pk in request.machines_keys {
        let encrypted_value = pk
            .encrypt(request.secret_value.clone())
            .map_err(|err| JsError::new(&format!("Error encrypting secret: {}", err)))?;

        machines_values.push(MachineUpdateValue {
            target: pk.id,
            encrypted_value,
            data_type: SecretDataType::Text,
            name: request.name.clone(),
            environment: request.env_name.clone(),
            tag: request.tag_name.clone(),
        });
    }

    let result = EncryptSecretResult {
        auth_response,
        machines_values,
        contributors_values,
    }
    .into_ts()?;

    Ok(result)
}

#[derive(Deserialize, Tsify)]
pub struct DecryptSecretRequest {
    auth_request: DecryptionAuthorizationRequest,
    encrypted_secrets: Vec<(ContributorPublicKey, ContributorSecretValue)>,
}

#[derive(Deserialize, Serialize, Tsify)]
pub struct DecryptedSecret {
    env_name: String,
    name: String,
    tag: String,
    plain_value: String,
}

#[derive(Deserialize, Serialize, Tsify)]
pub struct DecryptSecretResult {
    decrypted_secrets: Vec<DecryptedSecret>,
}

#[wasm_bindgen]
pub async fn decrypt_secrets(
    ts_request: Ts<DecryptSecretRequest>,
) -> Result<Ts<DecryptSecretResult>, JsError> {
    let request: DecryptSecretRequest = ts_request.to_rust()?;

    let (auth_response, session) = request
        .auth_request
        .authorize()
        .await
        .map_err(|err| JsError::new(&format!("Error authorizing user: {}", err)))?;

    let cred_secrets = request
        .encrypted_secrets
        .iter()
        .filter(|(key, _)| &key.cred_id == &auth_response.id);

    let mut decrypted_secrets: Vec<DecryptedSecret> = Vec::new();

    for (_, value) in cred_secrets {
        let plain_value = session
            .decrypt(&value.encrypted_value)
            .map_err(|err| JsError::new(&format!("Error decrypting secret: {}", err)))?;
        decrypted_secrets.push(DecryptedSecret {
            tag: value.tag.clone(),
            plain_value,
            name: value.name.clone(),
            env_name: value.env_name.clone(),
        });
    }

    let result = DecryptSecretResult { decrypted_secrets };

    Ok(result.into_ts()?)
}

#[derive(Deserialize, Tsify)]
pub struct ReEncryptPackageRequest {
    auth_request: DecryptionAuthorizationRequest,
    machine_keys: Vec<SimpleMachinePublicKey>,
    contributor_keys: Vec<SimpleContributorPublicKey>,
    encrypted_secrets: Vec<(ContributorPublicKey, ContributorSecretValue)>,
}

#[derive(Serialize, Tsify)]
pub struct ReEncryptPackageResult {
    auth_response: PasskeyAuthorizationResult,
    machines_values: Vec<MachineUpdateValue>,
    contributors_values: Vec<ContributorUpdateValue>,
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

    let mut machines_values: Vec<MachineUpdateValue> = Default::default();
    let mut contributors_values: Vec<ContributorUpdateValue> = Default::default();

    let cred_secrets = request
        .encrypted_secrets
        .iter()
        .filter(|(key, _)| key.cred_id == auth_response.id);

    for (_, value) in cred_secrets {
        let plain_value = session.decrypt(&value.encrypted_value).map_err(|err| {
            JsError::new(&format!(
                "Error decrypting {}/{}/{}: {}",
                value.env_name, value.name, value.tag, err
            ))
        })?;
        for machine_key in request.machine_keys.iter() {
            let encrypted_value = machine_key.encrypt(plain_value.clone()).map_err(|err| {
                JsError::new(&format!(
                    "Error encrypting {}/{}/{}: {}",
                    value.env_name, value.name, value.tag, err
                ))
            })?;
            machines_values.push(MachineUpdateValue {
                tag: value.tag.clone(),
                name: value.name.clone(),
                environment: value.env_name.clone(),
                encrypted_value,
                data_type: SecretDataType::Text,
                target: machine_key.id.clone(),
            })
        }
        for contributor_key in request.contributor_keys.iter() {
            let encrypted_value = contributor_key
                .encrypt(plain_value.clone())
                .map_err(|err| {
                    JsError::new(&format!(
                        "Error encrypting {}/{}/{}: {}",
                        value.env_name, value.name, value.tag, err
                    ))
                })?;
            contributors_values.push(ContributorUpdateValue {
                tag: value.tag.clone(),
                name: value.name.clone(),
                environment: value.env_name.clone(),
                encrypted_value,
                data_type: SecretDataType::Text,
                target: contributor_key.id,
            })
        }
    }

    let result = ReEncryptPackageResult {
        auth_response,
        machines_values,
        contributors_values,
    }
    .into_ts()?;

    Ok(result)
}
