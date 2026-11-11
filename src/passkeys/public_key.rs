use crate::passkeys::authorize::PasskeyAuthorizationResult;
use serde::{Deserialize, Serialize};
use ts_rs::TS;
use tsify::Tsify;

#[derive(Serialize, Deserialize, Debug, Clone, Tsify, TS)]
pub struct PublicKeyGenerateResult {
    pub public_key: String,
    pub auth_result: PasskeyAuthorizationResult,
}
