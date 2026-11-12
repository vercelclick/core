use click_core::{AuthSession, AuthTokenClaims, InternalError, InternalResult, StatusCode, caller};
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode};
use std::sync::LazyLock;

static DECODING_KEY: LazyLock<DecodingKey> =
    LazyLock::new(|| DecodingKey::from_ed_pem(env!("JWT_CLOUD_PUBLIC_KEY").as_bytes()).unwrap());

pub fn verify_session_token(token: &str) -> InternalResult<AuthSession> {
    let validation = Validation::new(Algorithm::EdDSA);

    let token_data =
        decode::<AuthTokenClaims>(token, &DECODING_KEY, &validation).map_err(|err| {
            InternalError::trace(
                caller!(),
                StatusCode::UNAUTHORIZED,
                "Invalid authorization token, create a new session and retry",
                err,
            )
        })?;

    Ok(token_data.claims.make_session())
}
