use jwt_simple::prelude::{Ed25519PublicKey, EdDSAPublicKeyLike};
use secretpass_core::{AuthSession, AuthTokenClaims};
use serde::Serialize;
use std::sync::LazyLock;
use tsify::{Ts, Tsify};
use wasm_bindgen::JsError;
use wasm_bindgen::prelude::wasm_bindgen;

static CLOUD_PUBLIC_KEY: LazyLock<Ed25519PublicKey> = LazyLock::new(|| {
    Ed25519PublicKey::from_bytes(env!("JWT_CLOUD_PUBLIC_KEY").as_bytes()).unwrap()
});

#[derive(Serialize, Tsify)]
pub struct TsAuthSession(pub AuthSession);

#[wasm_bindgen]
pub fn check_session_token(token: &str) -> Result<Ts<TsAuthSession>, JsError> {
    let token_data = CLOUD_PUBLIC_KEY
        .verify_token::<AuthTokenClaims>(&token, None)
        .map_err(|_| JsError::new("Error verifying session token"))?;

    let result = TsAuthSession(token_data.custom.make_session()).into_ts()?;

    Ok(result)
}
