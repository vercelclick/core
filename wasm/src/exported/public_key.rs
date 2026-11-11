use crate::auth::DecryptionAuthorizationRequest;
use secretpass_core::passkeys::authorize::PasskeyAuthorizationResult;
use serde::{Deserialize, Serialize};
use tsify::{Ts, Tsify};
use wasm_bindgen::JsError;
use wasm_bindgen::prelude::wasm_bindgen;

#[derive(Serialize, Deserialize, Debug, Clone, Tsify)]
pub struct PublicKeyGenerateResult {
    pub public_key: String,
    pub auth_result: PasskeyAuthorizationResult,
}

#[wasm_bindgen]
pub async fn generate_public_keys(
    ts_request: Ts<DecryptionAuthorizationRequest>,
) -> Result<Ts<PublicKeyGenerateResult>, JsError> {
    let request = ts_request.to_rust()?;

    let (auth_response, session) = request.authorize().await.map_err(JsError::from)?;

    let public_key = session.public_key();

    let response = PublicKeyGenerateResult {
        public_key: public_key.encode(),
        auth_result: auth_response,
    }
    .into_ts()?;

    Ok(response)
}
