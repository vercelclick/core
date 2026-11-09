use crate::auth::helpers::{get_credentials_container, parse_promise};
use crate::auth::mapping::{
    build_credential_request_extensions, build_credentials_array,
    map_browser_passkey_registration_response,
};
use serde::{Deserialize, Serialize};
use tsify::Tsify;

use crate::passkeys::{RP_ENTITY_ID, RP_ENTITY_NAME};
use secretpass_core::passkeys::create::PasskeyCreationResult;
use secretpass_core::utils::bin_decode;
use secretpass_core::{InternalError, InternalResult, StatusCode, source};
use wasm_bindgen::JsValue;
use web_sys::js_sys::{Array as JsArray, Object as JsObject, Reflect as JsReflect};
use web_sys::{
    AttestationConveyancePreference, AuthenticatorSelectionCriteria, CredentialCreationOptions,
    PublicKeyCredentialCreationOptions, PublicKeyCredentialRpEntity, PublicKeyCredentialUserEntity,
    UserVerificationRequirement,
};

#[derive(Debug, Serialize, Deserialize, Tsify)]
pub struct PasskeyCreationRequest {
    pub exclude_keys: Vec<String>,
    pub email: String,
    pub full_name: String,
    pub user_id: String,
    pub challenge: String,
}

impl PasskeyCreationRequest {
    pub(crate) async fn attempt(&self) -> InternalResult<PasskeyCreationResult> {
        register_user(self).await
    }
}

async fn register_user(params: &PasskeyCreationRequest) -> InternalResult<PasskeyCreationResult> {
    let rp = PublicKeyCredentialRpEntity::new(RP_ENTITY_NAME);
    rp.set_id(RP_ENTITY_ID);

    let user_id = params.user_id.clone();
    let mut user_id_bytes: Vec<u8> = user_id.into_bytes();
    let user = PublicKeyCredentialUserEntity::new_with_u8_slice(
        &params.email,
        &params.full_name,
        &mut user_id_bytes,
    );

    // Request PRF extension during key creation, this is a dealbreaker if not supported
    let extensions = build_credential_request_extensions(None);

    let mut challenge = bin_decode(&params.challenge)?;
    let pk_options = PublicKeyCredentialCreationOptions::new_with_u8_slice(
        &mut challenge,
        &build_credential_params(),
        &rp,
        &user,
    );

    // Allow the user up to 60 seconds to complete the registration
    pk_options.set_timeout(60_000);
    pk_options.set_extensions(&extensions);
    pk_options.set_attestation(AttestationConveyancePreference::Indirect);

    if !params.exclude_keys.is_empty() {
        pk_options.set_exclude_credentials(&build_credentials_array(&params.exclude_keys)?)
    }

    let selection = AuthenticatorSelectionCriteria::new();
    selection.set_user_verification(UserVerificationRequirement::Required);
    selection.set_resident_key("preferred");

    pk_options.set_authenticator_selection(&selection);

    let options = CredentialCreationOptions::new();
    options.set_public_key(&pk_options);

    let promise = get_credentials_container()?
        .create_with_options(&options)
        .map_err(|err| InternalError::trace(source!(),StatusCode::UNAUTHORIZED, "Error creating passkey, please retry, if the issue persists, raise a support request", err))?;

    let credential = parse_promise(promise).await?;

    map_browser_passkey_registration_response(credential)
}

fn build_credential_params() -> JsArray {
    let params = JsArray::new();
    // -8: Highly secure EdDSA (Ed25519)
    // -7: Universally supported ES256 (P-256)
    for algorithm in [-8, -7] {
        let params_object = JsObject::new();
        JsReflect::set(
            &params_object,
            &JsValue::from_str("type"),
            &JsValue::from_str("public-key"),
        )
        .unwrap();
        JsReflect::set(
            &params_object,
            &JsValue::from_str("alg"),
            &JsValue::from(algorithm),
        )
        .unwrap();
        params.push(&params_object);
    }
    params
}
