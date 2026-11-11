use secretpass_core::{AuthTokenClaims, InternalError, InternalResult, StatusCode, constants};
use std::sync::LazyLock;

static ENCODING_KEY: LazyLock<jsonwebtoken::EncodingKey> = LazyLock::new(|| {
    jsonwebtoken::EncodingKey::from_ed_pem(env!("JWT_CLOUD_PRIVATE_KEY").as_bytes()).unwrap()
});

pub fn create_backend_session_token(
    session: secretpass_core::Session,
    user: secretpass_core::User,
    passkeys: Vec<secretpass_core::Passkey>,
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

    jsonwebtoken::encode(&jsonwebtoken::Header::default(), &claims, &ENCODING_KEY).map_err(|err| {
        InternalError::trace(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Error encoding session token",
            err,
        )
    })
}
