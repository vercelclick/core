use chrono::Utc;
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation, decode, encode};
use secretpass_core::constants::{RP_ID, RP_ORIGIN};
use secretpass_core::{
    AuthSession, AuthTokenClaims, InternalError, InternalResult, Passkey, Session, StatusCode, User,
};
use std::sync::LazyLock;

const SERVICE_BASE_URL: &str = env!("SERVICE_BASE_URL");

#[cfg(feature = "session-maker")]
static ENCODING_KEY: LazyLock<EncodingKey> =
    LazyLock::new(|| EncodingKey::from_ed_pem(env!("JWT_BACKEND_PRIVATE_KEY").as_bytes()).unwrap());

#[cfg(feature = "session-maker")]
pub fn create_backend_session_token(
    session: Session,
    user: User,
    passkeys: Vec<Passkey>,
) -> InternalResult<String> {
    let now = Utc::now().timestamp() as u64;
    let exp = session.expires_on.timestamp() as u64;

    let claims = AuthTokenClaims {
        exp,
        iat: now,
        sub: session.id,
        iss: SERVICE_BASE_URL.to_string(),
        aud: RP_ORIGIN.to_string(),

        user,
        passkeys,
    };

    encode(&Header::default(), &claims, &ENCODING_KEY).map_err(|err| {
        InternalError::trace(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Error encoding session token",
            err,
        )
    })
}

static DECODING_KEY: LazyLock<DecodingKey> =
    LazyLock::new(|| DecodingKey::from_ed_pem(env!("JWT_FRONTEND_PUBLIC_KEY").as_bytes()).unwrap());

pub fn verify_frontend_session_token(token: &str, path: &str) -> InternalResult<AuthSession> {
    let mut validation = Validation::new(Algorithm::EdDSA);

    let audience = format!("{SERVICE_BASE_URL}{path}");

    validation.set_audience(&[audience]);
    validation.set_issuer(&[RP_ID]);
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
