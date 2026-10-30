use crate::auth::AuthorizationRequest;
use secretpass_core::passkeys::authorize::PasskeyAuthorizationResult;
use tsify::{Ts, Tsify};
use wasm_bindgen::JsError;
use wasm_bindgen::prelude::wasm_bindgen;

#[wasm_bindgen]
pub async fn authorize_operation(
    params: Ts<AuthorizationRequest>,
) -> Result<Ts<PasskeyAuthorizationResult>, JsError> {
    let params: AuthorizationRequest = params.to_rust()?;

    let result = params
        .authorize()
        .await
        .map_err(|err| JsError::new(&format!("Error authorizing user: {}", err)))?;

    let result = result.into_ts()?;

    Ok(result)
}
