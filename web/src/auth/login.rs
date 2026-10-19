use crate::auth::helpers::{get_credentials_container, parse_promise};
use crate::auth::mapping::{
    allowed_credentials, build_credential_request_extensions, build_prf_eval_values,
    map_browser_passkey_authentication,
};
use crate::passkeys::finish_login;
use crate::passkeys::protocol::RP_ENTITY_ID;
use crate::passkeys::types::{LoginResponse, PrfResults};
use crate::session::SecureSession;
use secretpass_core::utils::bin_decode;
use secretpass_core::{EncryptionAlgorithm, SecretpassPasskey};
use serde::{Deserialize, Serialize};
use tsify::Tsify;
use web_sys::{
    CredentialRequestOptions, PublicKeyCredentialRequestOptions, UserVerificationRequirement,
};

#[derive(Debug, Clone, Serialize, Deserialize, Tsify)]
pub struct PrfDeriveConfig {
    algorithm: EncryptionAlgorithm,
    user_salt: Vec<String>,   // The logged-in secretpass user
    entity_salt: Vec<String>, // Can be workspace or project
}

#[derive(Debug, Clone, Serialize, Deserialize, Tsify)]
pub struct LoginParams {
    challenge: String,
    passkeys: Vec<SecretpassPasskey>,
    prf_config: Option<PrfDeriveConfig>,
}

impl LoginParams {
    fn challenge(&self) -> anyhow::Result<Vec<u8>> {
        bin_decode(&self.challenge)
    }
}

pub async fn login_user_bounded(
    params: &LoginParams,
) -> anyhow::Result<(SecretpassPasskey, LoginResponse, Option<SecureSession>)> {
    let challenge = params.challenge()?;

    let (passkey, login_response, prf_results) = browser_user_login(&params).await?;

    finish_login(&passkey, &challenge, &login_response).await?;

    let session = if let Some(config) = &params.prf_config {
        if let Some(prf_results) = prf_results {
            Some(SecureSession::new(config.algorithm, prf_results)?)
        } else {
            return Err(anyhow::anyhow!(
                "PRF results not found, we can't derive private key!"
            ));
        }
    } else {
        None
    };

    Ok((passkey, login_response, session))
}

async fn browser_user_login(
    params: &LoginParams,
) -> anyhow::Result<(SecretpassPasskey, LoginResponse, Option<PrfResults>)> {
    let mut challenge = params.challenge()?;

    let pk_options = PublicKeyCredentialRequestOptions::new_with_u8_slice(&mut challenge);
    pk_options.set_rp_id(RP_ENTITY_ID);
    pk_options.set_allow_credentials(&allowed_credentials(&params.passkeys)?);
    pk_options.set_user_verification(UserVerificationRequirement::Required);

    // Not every login requires PRF
    if let Some(config) = params.prf_config.clone() {
        let prf_values = build_prf_eval_values(config.user_salt, config.entity_salt);
        let extensions = build_credential_request_extensions(Some(prf_values));
        pk_options.set_extensions(&extensions);
    }

    let options = CredentialRequestOptions::new();
    options.set_public_key(&pk_options);

    let promise = match get_credentials_container()?.get_with_options(&options) {
        Ok(promise) => promise,
        Err(err) => return Err(anyhow::format_err!("Error getting passkey: {:?}", err)),
    };

    let credential = parse_promise(promise).await?;

    map_browser_passkey_authentication(credential, &params.passkeys)
}
