use click_core::passkeys::authorize::PasskeyAuthorizationResult;
use serde::{Deserialize, Serialize};
use ts_rs::TS;

#[derive(Debug, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct PasskeySignInRequest {
    pub owner: String,
    pub auth_response: PasskeyAuthorizationResult,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct EmailSignInRequest {
    pub email_address: String,
    pub confirmation_code: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct AuthTokenResponse {
    pub token: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct WebauthnChallengeResponse {
    pub challenge: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct WebauthnChallengeAnonymousResponse {
    pub owner: String,
    pub challenge: String,
}
