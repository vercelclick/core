use crate::auth::PasskeyCreationRequest;
use crate::passkeys::creation::PasskeyCreationResponse;
use tsify::{Ts, Tsify};
use wasm_bindgen::JsError;
use wasm_bindgen::prelude::wasm_bindgen;

#[wasm_bindgen]
pub async fn create_passkey(
    request: Ts<PasskeyCreationRequest>,
) -> Result<Ts<PasskeyCreationResponse>, JsError> {
    let request: PasskeyCreationRequest = request.to_rust()?;

    let response = request
        .attempt()
        .await
        .map_err(|err| JsError::new(&format!("Error registering user: {:?}", err)))?;
    let response = response.into_ts()?;

    Ok(response)
}
