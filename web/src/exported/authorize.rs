use crate::auth::AuthorizationRequest;
use crate::passkeys::authorize::AuthorizationResponse;
use tsify::{Ts, Tsify};
use wasm_bindgen::JsError;
use wasm_bindgen::prelude::wasm_bindgen;

#[wasm_bindgen]
pub async fn authorize_operation(
    params: Ts<AuthorizationRequest>,
) -> Result<Ts<AuthorizationResponse>, JsError> {
    let params: AuthorizationRequest = params.to_rust()?;

    let result = params
        .authorize()
        .await
        .map_err(|err| JsError::new(&format!("Error authorizing user: {}", err)))?;

    let result = result.into_ts()?;

    Ok(result)
}
