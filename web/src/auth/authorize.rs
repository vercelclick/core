use crate::auth::helpers::{get_credentials_container, parse_promise};
use crate::auth::mapping::{
    build_credential_request_extensions, build_credentials_array, build_prf_eval_values,
    map_browser_passkey_authentication,
};
use crate::passkeys::authorize::PasskeyAuthorizationResponse;
use crate::passkeys::prf::{PrfDeriveConfig, PrfResults};
use crate::passkeys::protocol::RP_ENTITY_ID;
use crate::session::SecureSession;
use secretpass_core::utils::bin_decode;
use serde::{Deserialize, Serialize};
use tsify::Tsify;
use web_sys::{
    CredentialRequestOptions, PublicKeyCredentialRequestOptions, UserVerificationRequirement,
};

#[derive(Debug, Clone, Serialize, Deserialize, Tsify)]
pub struct AuthorizationRequest {
    challenge: String,
    allowed_credentials: Option<Vec<String>>,
}

impl AuthorizationRequest {
    pub(crate) async fn authorize(&self) -> anyhow::Result<PasskeyAuthorizationResponse> {
        let (response, _) =
            browser_user_authorize(&self.challenge, &self.allowed_credentials, &None).await?;
        Ok(response)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Tsify)]
pub struct DecryptionAuthorizationRequest {
    challenge: String,
    allowed_credentials: Vec<String>,
    prf_config: PrfDeriveConfig,
}

impl DecryptionAuthorizationRequest {
    pub(crate) async fn authorize(
        &self,
    ) -> anyhow::Result<(PasskeyAuthorizationResponse, SecureSession)> {
        let (login_response, prf_results) = browser_user_authorize(
            &self.challenge,
            &Some(self.allowed_credentials.clone()),
            &Some(self.prf_config.clone()),
        )
        .await?;

        let session = prf_results
            .map(|results| SecureSession::new(self.prf_config.algorithm, results))
            .ok_or_else(|| anyhow::anyhow!("Missing Pseudo Random Function results!"))??;

        Ok((login_response, session))
    }
}

async fn browser_user_authorize(
    challenge: &str,
    allowed_credentials: &Option<Vec<String>>,
    prf_config: &Option<PrfDeriveConfig>,
) -> anyhow::Result<(PasskeyAuthorizationResponse, Option<PrfResults>)> {
    let mut challenge = bin_decode(challenge)?;

    let pk_options = PublicKeyCredentialRequestOptions::new_with_u8_slice(&mut challenge);
    pk_options.set_rp_id(RP_ENTITY_ID);
    if let Some(allowed_credentials) = allowed_credentials {
        pk_options.set_allow_credentials(&build_credentials_array(allowed_credentials)?);
    }
    pk_options.set_user_verification(UserVerificationRequirement::Required);

    // Not every login requires PRF
    if let Some(config) = prf_config.clone() {
        let (user_salt, entity_salt) = config.get_salts();
        let prf_values = build_prf_eval_values(user_salt, entity_salt);
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

    map_browser_passkey_authentication(credential)
}
