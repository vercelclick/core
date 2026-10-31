use crate::auth::PasskeyCreationRequest;
use secretpass_core::passkeys::create::PasskeyCreationResult;
use tsify::{Ts, Tsify};
use wasm_bindgen::JsError;
use wasm_bindgen::prelude::wasm_bindgen;

#[wasm_bindgen]
pub async fn create_passkey(
    request: Ts<PasskeyCreationRequest>,
) -> Result<Ts<PasskeyCreationResult>, JsError> {
    let request: PasskeyCreationRequest = request.to_rust()?;

    let response = request
        .attempt()
        .await
        .map_err(|err| JsError::new(&err.to_string()))?;
    let response = response.into_ts()?;

    Ok(response)
}
