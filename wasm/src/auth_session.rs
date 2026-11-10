use chrono::Utc;
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation, decode, encode};
use secretpass_core::{AuthSession, AuthTokenClaims};
use std::sync::LazyLock;
use tsify::{Ts, Tsify};
use wasm_bindgen::JsError;
use wasm_bindgen::prelude::wasm_bindgen;

static DECODING_KEY: LazyLock<DecodingKey> =
    LazyLock::new(|| DecodingKey::from_ed_pem(env!("JWT_BACKEND_PUBLIC_KEY").as_bytes()).unwrap());

const CLOUD_BASE_URL: &str = env!("CLOUD_BASE_URL");

pub fn verify_backend_token_internal(token: &str) -> Result<AuthTokenClaims, JsError> {
    let mut validation = Validation::new(Algorithm::EdDSA);

    let window = web_sys::window().unwrap();

    let origin = window.location().origin().unwrap();

    validation.set_audience(&[origin]);
    validation.set_issuer(&[CLOUD_BASE_URL]);
    validation.set_required_spec_claims(&["exp", "sub", "iss", "aud"]);

    let token_data = decode::<AuthTokenClaims>(token, &DECODING_KEY, &validation)
        .map_err(|_| JsError::new("Error verifying session token"))?;
    Ok(token_data.claims)
}

#[wasm_bindgen]
pub fn verify_backend_token(token: &str) -> Result<Ts<AuthSession>, JsError> {
    let claims = verify_backend_token_internal(token)?;

    let session = claims.make_session().into_ts()?;

    Ok(session)
}

static ENCODING_KEY: LazyLock<EncodingKey> = LazyLock::new(|| {
    EncodingKey::from_ed_pem(env!("JWT_FRONTEND_PRIVATE_KEY").as_bytes()).unwrap()
});

#[wasm_bindgen]
pub fn create_authorization_token(
    backend_token: &str,
    endpoint: String,
) -> Result<String, JsError> {
    let window = web_sys::window().unwrap();

    let origin = window.location().origin().unwrap();

    let now = Utc::now().timestamp() as u64;
    let exp = now + 15; // Token lives for only 15 seconds

    let backend_claims = verify_backend_token_internal(backend_token)?;

    let claims = AuthTokenClaims {
        exp,
        iat: now,
        iss: origin,
        aud: endpoint.to_string(),
        sub: backend_claims.sub,

        user: backend_claims.user,
        passkeys: backend_claims.passkeys,
    };

    encode(&Header::default(), &claims, &ENCODING_KEY)
        .map_err(|_| JsError::new("Error encoding authorization token"))
}
