use crate::auth::helpers::{get_credentials_container, parse_promise};
use crate::auth::mapping::{
    build_credential_request_extensions, build_credentials_array, build_prf_eval_values,
    map_browser_passkey_authentication,
};
use crate::passkeys::authorize::PasskeyAuthorizationResult;
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
    allowed_credentials: Vec<String>,
}

impl AuthorizationRequest {
    pub(crate) async fn authorize(&self) -> anyhow::Result<PasskeyAuthorizationResult> {
        let (response, _) =
            browser_user_authorize(&self.challenge, &self.allowed_credentials, &None).await?;
        Ok(response)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Tsify)]
pub struct DecryptionAuthorizationRequest {
    challenge: String,
    prf_configs: Vec<PrfDeriveConfig>,
}

impl DecryptionAuthorizationRequest {
    pub(crate) async fn authorize(
        &self,
    ) -> anyhow::Result<(PasskeyAuthorizationResult, SecureSession)> {
        let allowed_credentials: Vec<String> = self
            .prf_configs
            .iter()
            .map(|conf| conf.cred_id.clone())
            .collect();

        let (login_response, prf_results) = browser_user_authorize(
            &self.challenge,
            &allowed_credentials,
            &Some(self.prf_configs.clone()),
        )
        .await?;

        let session = prf_results
            .map(SecureSession::new)
            .ok_or_else(|| anyhow::anyhow!("Missing Pseudo Random Function results!"))??;

        Ok((login_response, session))
    }
}

async fn browser_user_authorize(
    challenge: &str,
    allowed_credentials: &[String],
    prf_configs: &Option<Vec<PrfDeriveConfig>>,
) -> anyhow::Result<(PasskeyAuthorizationResult, Option<PrfResults>)> {
    let mut challenge = bin_decode(challenge)?;

    let pk_options = PublicKeyCredentialRequestOptions::new_with_u8_slice(&mut challenge);
    pk_options.set_rp_id(RP_ENTITY_ID);
    pk_options.set_allow_credentials(&build_credentials_array(allowed_credentials)?);
    pk_options.set_user_verification(UserVerificationRequirement::Required);

    // Not every login requires PRF
    if let Some(configs) = prf_configs.clone()
        && !configs.is_empty()
    {
        let prf_values = build_prf_eval_values(&configs);
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
