use crate::auth::{RegistrationParams, register_user_bounded};
use crate::passkeys::types::RegistrationResponse;
use secretpass_core::SecretpassPasskey;
use serde::Serialize;
use tsify::{Ts, Tsify};
use wasm_bindgen::JsError;
use wasm_bindgen::prelude::wasm_bindgen;

#[derive(Debug, Clone, Serialize, Tsify)]
pub struct RegistrationResult {
    passkey: SecretpassPasskey,
    registration_response: RegistrationResponse,
}

#[wasm_bindgen]
pub async fn register_user(
    params: Ts<RegistrationParams>,
) -> Result<Ts<RegistrationResult>, JsError> {
    let params: RegistrationParams = params.to_rust()?;

    let (passkey, registration_response) = register_user_bounded(params)
        .await
        .map_err(|err| JsError::new(&format!("Error registering user: {:?}", err)))?;

    let result = RegistrationResult {
        passkey,
        registration_response,
    }
    .into_ts()?;

    Ok(result)
}
