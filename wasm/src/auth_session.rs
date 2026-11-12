use click_core::{AuthSession, Passkey, User};
use jwt_simple::prelude::{Deserialize, Ed25519PublicKey, EdDSAPublicKeyLike};
use serde::Serialize;
use std::str::FromStr;
use tsify::{Ts, Tsify};
use uuid::Uuid;
use wasm_bindgen::JsError;
use wasm_bindgen::prelude::wasm_bindgen;

#[derive(Serialize, Tsify)]
pub struct TsAuthSession(pub AuthSession);

#[derive(Debug, Deserialize)]
pub struct CustomClaims {
    pub user: User,
    pub passkeys: Vec<Passkey>,
}

#[wasm_bindgen]
pub fn check_session_token(token: &str) -> Result<Ts<TsAuthSession>, JsError> {
    let public_key = Ed25519PublicKey::from_pem(env!("JWT_CLOUD_PUBLIC_KEY"))
        .map_err(|err| JsError::new(&format!("Error parsing JWT public key {:?}", err)))?;

    let token_data = public_key
        .verify_token::<CustomClaims>(&token, None)
        .map_err(|err| JsError::new(&format!("Error verifying session token: {:?}", err)))?;

    let session = AuthSession {
        id: Uuid::from_str(
            &token_data
                .subject
                .ok_or_else(|| JsError::new("Invalid session token, subject missing"))?,
        )
        .map_err(|_| JsError::new("Invalid session id"))?,
        user: token_data.custom.user,
        passkeys: token_data.custom.passkeys,
    };

    let result = TsAuthSession(session).into_ts()?;

    Ok(result)
}
