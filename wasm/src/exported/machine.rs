use crate::auth::DecryptionAuthorizationRequest;
use secretpass_core::passkeys::authorize::PasskeyAuthorizationResult;
use secretpass_core::{
    ContributorPublicKey, ContributorSecretValue, KeyPair, PrivateKeySeed, SecretValue,
    TargetedPublicKey,
};
use serde::{Deserialize, Serialize};
use tsify::{Ts, Tsify};
use uuid::Uuid;
use wasm_bindgen::JsError;
use wasm_bindgen::prelude::wasm_bindgen;

#[derive(Deserialize, Tsify)]
pub struct GenerateMachineKeyRequest {
    project_id: Uuid,
    auth_request: DecryptionAuthorizationRequest,
    encrypted_secrets: Vec<(ContributorPublicKey, ContributorSecretValue)>,
}

#[derive(Serialize, Tsify)]
pub struct GenerateMachineKeyResult {
    auth_result: PasskeyAuthorizationResult,
    private_key: String,
    public_key: TargetedPublicKey,
    encrypted_values: Vec<SecretValue>,
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
        .map_err(JsError::from)?;

    let (private_key, seed) = PrivateKeySeed::generate_access_key(request.project_id);

    let public_key = KeyPair::from_seed(seed)
        .map_err(JsError::from)?
        .public_key();

    let targeted_key = TargetedPublicKey {
        target: public_key.access_key_id(),
        value: public_key.encode(),
    };

    let cred_secrets = request
        .encrypted_secrets
        .iter()
        .filter(|(key, _)| key.cred_id == auth_response.id);

    let mut encrypted_values: Vec<SecretValue> = Vec::new();
    for (_, value) in cred_secrets {
        encrypted_values.extend_from_slice(
            &session
                .reencrypt_value(value, std::slice::from_ref(&targeted_key))
                .map_err(JsError::from)?,
        );
    }

    let result = GenerateMachineKeyResult {
        auth_result: auth_response,
        public_key: targeted_key,
        private_key,
        encrypted_values,
    }
    .into_ts()?;

    Ok(result)
}
