use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode};
use secretpass_core::constants;
use secretpass_core::{AuthSession, AuthTokenClaims, InternalError, InternalResult, StatusCode};
use std::sync::LazyLock;

const SERVICE_BASE_URL: &str = env!("SERVICE_BASE_URL");

static DECODING_KEY: LazyLock<DecodingKey> =
    LazyLock::new(|| DecodingKey::from_ed_pem(env!("JWT_FRONTEND_PUBLIC_KEY").as_bytes()).unwrap());

pub fn verify_frontend_session_token(token: &str, path: &str) -> InternalResult<AuthSession> {
    let mut validation = Validation::new(Algorithm::EdDSA);

    let audience = format!("{SERVICE_BASE_URL}{path}");

    validation.set_audience(&[audience]);
    validation.set_issuer(&[constants::RP_ID]);
    validation.set_required_spec_claims(&["exp", "sub", "iss", "aud"]);

    let token_data =
        decode::<AuthTokenClaims>(token, &DECODING_KEY, &validation).map_err(|err| {
            InternalError::trace(
                StatusCode::UNAUTHORIZED,
                "Invalid authorization token, create a new session and retry",
                err,
            )
        })?;

    Ok(token_data.claims.make_session())
}
