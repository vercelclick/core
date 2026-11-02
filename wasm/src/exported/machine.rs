use crate::auth::DecryptionAuthorizationRequest;
use secretpass_core::enums::{EncryptionAlgorithm, SecretDataType};
use secretpass_core::passkeys::authorize::PasskeyAuthorizationResult;
use secretpass_core::{
    ContributorPublicKey, ContributorSecretValue, MachineUpdateValue, PrivateKey, PrivateKeySeed,
    PublicKeyEncrypt, SimpleMachinePublicKey,
};
use serde::{Deserialize, Serialize};
use tsify::{Ts, Tsify};
use uuid::Uuid;
use wasm_bindgen::JsError;
use wasm_bindgen::prelude::wasm_bindgen;

#[derive(Deserialize, Tsify)]
pub struct GenerateMachineKeyRequest {
    project_id: Uuid,
    algorithm: EncryptionAlgorithm,
    auth_request: DecryptionAuthorizationRequest,
    encrypted_secrets: Vec<(ContributorPublicKey, ContributorSecretValue)>,
}

#[derive(Serialize, Tsify)]
pub struct GenerateMachineKeyResult {
    auth_response: PasskeyAuthorizationResult,
    private_key: String,
    public_key: SimpleMachinePublicKey,
    machine_secrets: Vec<MachineUpdateValue>,
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

    let (private_key, seed) = PrivateKeySeed::generate_machine_key(request.project_id)
        .map_err(|err| JsError::new(&format!("Error generating machine key: {}", err)))?;

    let public_key = PrivateKey::from_seed(seed)
        .map_err(|err| JsError::new(&format!("Error getting private key from seed: {}", err)))?
        .public_key(request.algorithm);

    let public_key = SimpleMachinePublicKey {
        id: public_key.machine_key_id(),
        kem: public_key.kem(),
        ecc: public_key.ecc(),
    };

    let cred_secrets = request
        .encrypted_secrets
        .iter()
        .filter(|(key, _)| key.cred_id == auth_response.id);

    let mut machine_secrets: Vec<MachineUpdateValue> = Vec::new();
    for (_, value) in cred_secrets {
        let plain_value = session.decrypt(&value.encrypted_value).map_err(|err| {
            JsError::new(&format!(
                "Error decrypting {}/{}/{}: {}",
                value.env_name, value.name, value.tag, err
            ))
        })?;

        let encrypted_value = public_key.encrypt(plain_value).map_err(|err| {
            JsError::new(&format!(
                "Error encrypting {}/{}/{}: {}",
                value.env_name, value.name, value.tag, err
            ))
        })?;

        machine_secrets.push(MachineUpdateValue {
            tag: value.tag.clone(),
            name: value.name.clone(),
            environment: value.env_name.clone(),
            encrypted_value,
            data_type: SecretDataType::Text,
            target: public_key.id.clone(),
        })
    }

    let result = GenerateMachineKeyResult {
        auth_response,
        public_key,
        machine_secrets,
        private_key,
    }
    .into_ts()?;

    Ok(result)
}
