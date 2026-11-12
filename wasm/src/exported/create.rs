use crate::auth::PasskeyCreationRequest;
use click_core::passkeys::create::PasskeyCreationResult;
use serde::{Deserialize, Serialize};
use tsify::{Ts, Tsify};
use wasm_bindgen::JsError;
use wasm_bindgen::prelude::wasm_bindgen;

#[derive(Serialize, Deserialize, Tsify)]
pub struct TsPasskeyCreationResult(pub PasskeyCreationResult);

#[wasm_bindgen]
pub async fn create_passkey(
    request: Ts<PasskeyCreationRequest>,
) -> Result<Ts<TsPasskeyCreationResult>, JsError> {
    let request: PasskeyCreationRequest = request.to_rust()?;

    let result = request.attempt().await.map_err(JsError::from)?;
    let result = TsPasskeyCreationResult(result).into_ts()?;

    Ok(result)
}
