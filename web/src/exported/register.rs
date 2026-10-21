use crate::auth::{RegistrationRequest};
use tsify::{Ts, Tsify};
use wasm_bindgen::JsError;
use wasm_bindgen::prelude::wasm_bindgen;
use crate::passkeys::registration::RegistrationResponse;

#[wasm_bindgen]
pub async fn register_user(
    request: Ts<RegistrationRequest>,
) -> Result<Ts<RegistrationResponse>, JsError> {
    let request: RegistrationRequest = request.to_rust()?;

    let response = request.attempt()
        .await
        .map_err(|err| JsError::new(&format!("Error registering user: {:?}", err)))?;
    let response = response.into_ts()?;

    Ok(response)
}
