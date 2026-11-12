use click_core::{AuthTokenClaims, InternalError, InternalResult, StatusCode, caller, constants};
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use std::sync::LazyLock;

static ENCODING_KEY: LazyLock<EncodingKey> =
    LazyLock::new(|| EncodingKey::from_ed_pem(env!("JWT_CLOUD_PRIVATE_KEY").as_bytes()).unwrap());

pub fn create_backend_session_token(
    session: click_core::Session,
    user: click_core::User,
    passkeys: Vec<click_core::Passkey>,
) -> InternalResult<String> {
    let now = chrono::Utc::now().timestamp() as u64;
    let exp = session.expires_on.timestamp() as u64;

    let claims = AuthTokenClaims {
        exp,
        iat: now,
        sub: session.id,
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
