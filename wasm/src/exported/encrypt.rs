use crate::auth::{AuthorizationRequest, DecryptionAuthorizationRequest};
use chrono::Utc;
use click_core::enums::SecretDataType;
use click_core::passkeys::authorize::PasskeyAuthorizationResult;
use click_core::{ContributorPublicKey, SecretValue, TargetedPublicKey};
use serde::{Deserialize, Serialize};
use tsify::{Ts, Tsify};
use uuid::Uuid;
use wasm_bindgen::JsError;
use wasm_bindgen::prelude::wasm_bindgen;

#[derive(Deserialize, Tsify)]
pub struct EncryptSecretRequest {
    pub auth_request: AuthorizationRequest,
    pub keys: Vec<TargetedPublicKey>,
    pub name: String,
    pub env_name: String,
    pub tag_name: String,
    pub secret_value: String,
    #[tsify(type = "string")]
    pub project_id: Uuid,
}

#[derive(Debug, Clone, Serialize, Deserialize, Tsify)]
pub struct EncryptSecretResult {
    pub auth_result: PasskeyAuthorizationResult,
    pub encrypted_values: Vec<SecretValue>,
}

#[wasm_bindgen]
pub async fn encrypt_secret(
    ts_request: Ts<EncryptSecretRequest>,
) -> Result<Ts<EncryptSecretResult>, JsError> {
    let request: EncryptSecretRequest = ts_request.to_rust()?;

    let auth_result = request
        .auth_request
        .authorize()
        .await
        .map_err(JsError::from)?;

    let mut encrypted_values: Vec<SecretValue> = Vec::new();
    for pk in request.keys {
        let encrypted_value = pk
            .public_key()
            .map_err(JsError::from)?
            .encrypt(request.secret_value.clone())
            .map_err(JsError::from)?;
        encrypted_values.push(SecretValue {
            target: pk.target,
            encrypted_value,
            data_type: SecretDataType::Text,
            name: request.name.clone(),
            env_name: request.env_name.clone(),
            tag: request.tag_name.clone(),
            project_id: request.project_id,
            created_at: Utc::now(),
        });
    }

    let result = EncryptSecretResult {
        auth_result,
        encrypted_values,
    }
    .into_ts()?;

    Ok(result)
}

#[derive(Deserialize, Tsify)]
pub struct DecryptSecretRequest {
    auth_request: DecryptionAuthorizationRequest,
    encrypted_secrets: Vec<(ContributorPublicKey, SecretValue)>,
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

    let (auth_result, session) = request
        .auth_request
        .authorize()
        .await
        .map_err(JsError::from)?;

    let cred_secrets = request
        .encrypted_secrets
        .iter()
        .filter(|(key, _)| key.cred_id == auth_result.id);

    let mut decrypted_secrets: Vec<DecryptedSecret> = Vec::new();

    for (_, value) in cred_secrets {
        let plain_value = session
            .decrypt(&value.encrypted_value)
            .map_err(JsError::from)?;

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
    keys: Vec<TargetedPublicKey>,
    encrypted_secrets: Vec<(ContributorPublicKey, SecretValue)>,
}

#[derive(Serialize, Tsify)]
pub struct ReEncryptPackageResult {
    auth_response: PasskeyAuthorizationResult,
    encrypted_values: Vec<SecretValue>,
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
        .map_err(JsError::from)?;

    let mut encrypted_values: Vec<SecretValue> = Default::default();

    let cred_secrets = request
        .encrypted_secrets
        .iter()
        .filter(|(key, _)| key.cred_id == auth_response.id);

    for (_, value) in cred_secrets {
        encrypted_values.extend_from_slice(
            &session
                .reencrypt_value(value, &request.keys)
                .map_err(JsError::from)?,
        );
    }

    let result = ReEncryptPackageResult {
        auth_response,
        encrypted_values,
    }
    .into_ts()?;

    Ok(result)
}
