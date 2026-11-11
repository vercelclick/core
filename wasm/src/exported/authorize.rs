use crate::auth::AuthorizationRequest;
use secretpass_core::passkeys::authorize::PasskeyAuthorizationResult;
use serde::{Deserialize, Serialize};
use tsify::{Ts, Tsify};
use wasm_bindgen::JsError;
use wasm_bindgen::prelude::wasm_bindgen;

#[derive(Serialize, Deserialize, Tsify)]
pub struct TsPasskeyAuthorizationResult(PasskeyAuthorizationResult);

#[wasm_bindgen]
pub async fn authorize_operation(
    params: Ts<AuthorizationRequest>,
) -> Result<Ts<TsPasskeyAuthorizationResult>, JsError> {
    let params: AuthorizationRequest = params.to_rust()?;

    let result = params.authorize().await.map_err(JsError::from)?;

    let result = TsPasskeyAuthorizationResult(result).into_ts()?;

    Ok(result)
}
