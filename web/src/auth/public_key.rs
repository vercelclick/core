use crate::auth::DecryptionAuthorizationRequest;
use secretpass_core::enums::EncryptionAlgorithm;
use secretpass_core::passkeys::public_key::PublicKeyGenerateResult;
use tsify::{Ts, Tsify};
use wasm_bindgen::JsError;
use wasm_bindgen::prelude::wasm_bindgen;

#[wasm_bindgen]
pub async fn generate_public_keys(
    ts_request: Ts<DecryptionAuthorizationRequest>,
) -> Result<Ts<PublicKeyGenerateResult>, JsError> {
    let request = ts_request.to_rust()?;

    let (auth_response, session) = request
        .authorize()
        .await
        .map_err(|err| JsError::new(&format!("Error authorizing user: {}", err)))?;

    let public_key = session.public_key(EncryptionAlgorithm::Hybrid);

    let response = PublicKeyGenerateResult {
        ecc: public_key.ecc().unwrap(),
        kem: public_key.kem().unwrap(),
        auth_response,
    }
    .into_ts()?;

    Ok(response)
}
