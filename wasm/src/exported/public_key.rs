use crate::auth::DecryptionAuthorizationRequest;
use secretpass_core::passkeys::public_key::PublicKeyGenerateResult;
use tsify::{Ts, Tsify};
use wasm_bindgen::JsError;
use wasm_bindgen::prelude::wasm_bindgen;

#[wasm_bindgen]
pub async fn generate_public_keys(
    ts_request: Ts<DecryptionAuthorizationRequest>,
) -> Result<Ts<PublicKeyGenerateResult>, JsError> {
    let request = ts_request.to_rust()?;

    let (auth_response, session) = request.authorize().await.map_err(JsError::from)?;

    let public_key = session.public_key();

    let response = PublicKeyGenerateResult {
        public_key: public_key.encode(),
        auth_response,
    }
    .into_ts()?;

    Ok(response)
}
