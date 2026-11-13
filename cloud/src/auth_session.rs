use click_core::{
    InternalError, InternalResult, Passkey, Session, StatusCode, User, caller, constants,
};
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use serde::{Deserialize, Serialize};
use std::sync::LazyLock;

static ENCODING_KEY: LazyLock<EncodingKey> =
    LazyLock::new(|| EncodingKey::from_ed_pem(env!("JWT_CLOUD_PRIVATE_KEY").as_bytes()).unwrap());

#[derive(Debug, Clone, Serialize, Deserialize)]
struct AuthTokenClaims {
    sub: String,
    iss: String,
    aud: String, // Audience
    exp: u64,
    iat: u64,

    // Custom claims
    user: User,
    passkeys: Vec<Passkey>,
}

pub fn create_backend_session_token(
    session: Session,
    user: User,
    passkeys: Vec<Passkey>,
) -> InternalResult<String> {
    let now = chrono::Utc::now().timestamp() as u64;
    let exp = session.expires_on.timestamp() as u64;

    let claims = AuthTokenClaims {
        exp,
        iat: now,
        sub: session.id.to_string(),
        iss: "api.vercel.click".to_string(),
        aud: constants::RP_ORIGIN.to_string(),

        user,
        passkeys,
    };

    encode(&Header::new(Algorithm::EdDSA), &claims, &ENCODING_KEY).map_err(|err| {
        InternalError::trace(
            caller!(),
            StatusCode::INTERNAL_SERVER_ERROR,
            "Error encoding session token",
            err,
        )
    })
}
