use crate::auth::{LoginParams, login_user_bounded};
use crate::passkeys::types::LoginResponse;
use serde::{Deserialize, Serialize};
use tsify::{Ts, Tsify};
use wasm_bindgen::JsError;
use wasm_bindgen::prelude::wasm_bindgen;

#[derive(Debug, Clone, Serialize, Deserialize, Tsify)]
pub struct AuthorizeOperationResult {
    passkey_id: String,
    login_response: LoginResponse,
}

#[wasm_bindgen]
pub async fn authorize_operation(
    params: Ts<LoginParams>,
) -> Result<Ts<AuthorizeOperationResult>, JsError> {
    let params: LoginParams = params.to_rust()?;

    let (passkey, login_response, _) = login_user_bounded(&params)
        .await
        .map_err(|err| JsError::new(&format!("Error authorizing user: {}", err)))?;

    let result = AuthorizeOperationResult {
        passkey_id: passkey.id,
        login_response,
    };

    let result = result.into_ts()?;

    Ok(result)
}
