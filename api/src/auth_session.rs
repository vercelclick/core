use click_core::constants::RP_ORIGIN;
use click_core::{AuthSession, InternalError, InternalResult, Passkey, StatusCode, User, caller};
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode};
use serde::Deserialize;
use std::str::FromStr;
use std::sync::LazyLock;
use uuid::Uuid;

static DECODING_KEY: LazyLock<DecodingKey> =
    LazyLock::new(|| DecodingKey::from_ed_pem(env!("JWT_CLOUD_PUBLIC_KEY").as_bytes()).unwrap());

#[derive(Debug, Deserialize)]
struct CustomClaims {
    sub: String,
    user: User,
    passkeys: Vec<Passkey>,
}

pub fn verify_session_token(token: &str) -> InternalResult<AuthSession> {
    let mut validation = Validation::new(Algorithm::EdDSA);
    validation.set_audience(&[RP_ORIGIN]);

    let token_data = decode::<CustomClaims>(token, &DECODING_KEY, &validation).map_err(|err| {
        InternalError::trace(
            caller!(),
            StatusCode::UNAUTHORIZED,
            "Invalid authorization token, create a new session and retry",
            err,
        )
    })?;

    let session = AuthSession {
        id: Uuid::from_str(&token_data.claims.sub).map_err(|err| {
            InternalError::trace(
                caller!(),
                StatusCode::UNAUTHORIZED,
                "Invalid session token, subject missing",
                err,
            )
        })?,
        user: token_data.claims.user,
        passkeys: token_data.claims.passkeys,
    };

    Ok(session)
}
