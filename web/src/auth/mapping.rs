use crate::passkeys::authorize::{AssertionResponse, PasskeyAuthorizationResult};
use crate::passkeys::creation::{AttestationResponse, PasskeyCreationResult};
use crate::passkeys::prf::{PrfDeriveConfig, PrfResults};
use secretpass_core::utils::{bin_decode, sha256_raw};
use wasm_bindgen::{JsCast, JsValue};
use web_sys::js_sys::{
    Array as JsArray, ArrayBuffer, Object as JsObject, Reflect as JsReflect, Uint8Array,
};
use web_sys::{
    AuthenticationExtensionsClientInputs, AuthenticationExtensionsClientOutputs,
    AuthenticationExtensionsPrfInputs, AuthenticationExtensionsPrfValues,
    AuthenticatorAssertionResponse, AuthenticatorAttestationResponse, PublicKeyCredential,
};

fn prf_error(id: &str) -> anyhow::Error {
    anyhow::format_err!(
        "PRF_ERROR<{id}>: Browser not supported! Pseudo Random Functions extension is missing or disabled"
    )
}

fn get_prf_value(
    outputs: AuthenticationExtensionsClientOutputs,
) -> anyhow::Result<Option<JsValue>> {
    let prf_key = JsValue::from_str("prf");

    let prf_result = match JsReflect::get(&outputs, &prf_key) {
        Ok(prf_result) => prf_result,
        Err(_) => return Err(prf_error("01")),
    };
    if prf_result.is_undefined() || prf_result.is_null() {
        return Ok(None);
    }

    Ok(Some(prf_result))
}

pub fn map_browser_passkey_registration_response(
    pk_credential: PublicKeyCredential,
) -> anyhow::Result<PasskeyCreationResult> {
    let ext_outputs = pk_credential.get_client_extension_results();
    verify_prf_enabled(ext_outputs)?;

    let attestation_response = pk_credential
        .response()
        .dyn_into::<AuthenticatorAttestationResponse>()
        .map_err(|err| {
            anyhow::format_err!("Error parsing attestation response: {}", err.to_string())
        })?;

    let attestation_response = AttestationResponse {
        attestation_object: Uint8Array::new(&attestation_response.attestation_object()).to_vec(),
        client_data_json: Uint8Array::new(&attestation_response.client_data_json()).to_vec(),
    };

    let response = PasskeyCreationResult {
        id: pk_credential.id(),
        type_: pk_credential.type_(),
        response: attestation_response,
    };

    Ok(response)
}

pub fn verify_prf_enabled(outputs: AuthenticationExtensionsClientOutputs) -> anyhow::Result<()> {
    let prf_result = get_prf_value(outputs)?.ok_or_else(|| {
        anyhow::anyhow!(
            "Pseudo Random function not supported, please use a different passkey provider"
        )
    })?;

    let enabled = match JsReflect::get(&prf_result, &JsValue::from_str("enabled")) {
        Ok(value) => value,
        Err(_) => return Err(prf_error("09")),
    }
    .as_bool();

    if Some(true) != enabled {
        return Err(prf_error("10"));
    }

    Ok(())
}

pub fn parse_prf_result(
    outputs: AuthenticationExtensionsClientOutputs,
) -> anyhow::Result<Option<PrfResults>> {
    let prf_result = match get_prf_value(outputs)? {
        Some(results) => results,
        None => return Ok(None),
    };

    let results = match JsReflect::get(&prf_result, &JsValue::from_str("results")) {
        Ok(value) => value,
        Err(_) => return Err(prf_error("06")),
    };

    let first = match JsReflect::get(&results, &JsValue::from_str("first")) {
        Ok(value) => value,
        Err(_) => return Err(prf_error("07")),
    };
    let second = match JsReflect::get(&results, &JsValue::from_str("second")) {
        Ok(value) => value,
        Err(_) => return Err(prf_error("08")),
    };

    let first = parse_prf_value(first)?;
    let second = parse_prf_value(second)?;

    Ok(Some(PrfResults { first, second }))
}

pub fn map_browser_passkey_authentication(
    pk_credential: PublicKeyCredential,
) -> anyhow::Result<(PasskeyAuthorizationResult, Option<PrfResults>)> {
    let ext_outputs = pk_credential.get_client_extension_results();
    let prf_results = parse_prf_result(ext_outputs)?;

    let assertion_response = match pk_credential
        .response()
        .dyn_into::<AuthenticatorAssertionResponse>()
    {
        Ok(value) => value,
        Err(_) => return Err(anyhow::anyhow!("Error parsing assertion response")),
    };
    let user_handle = assertion_response.user_handle();

    let response = AssertionResponse {
        authenticator_data: Uint8Array::new(&assertion_response.authenticator_data()).to_vec(),
        client_data_json: Uint8Array::new(&assertion_response.client_data_json()).to_vec(),
        signature: Uint8Array::new(&assertion_response.signature()).to_vec(),
        user_handle: user_handle.map(|value| Uint8Array::new(&value).to_vec()),
    };

    let login_response = PasskeyAuthorizationResult {
        id: pk_credential.id(),
        type_: pk_credential.type_(),
        response,
    };

    Ok((login_response, prf_results))
}

pub fn parse_prf_value(buffer: JsValue) -> anyhow::Result<[u8; 32]> {
    let buffer = ArrayBuffer::from(buffer);
    let as_vec = Uint8Array::new(&buffer).to_vec();
    let value: [u8; 32] = match as_vec.try_into() {
        Ok(value) => value,
        Err(_) => return Err(anyhow::anyhow!("Error parsing PRF value")),
    };
    Ok(value)
}

pub fn build_credentials_array(credential_ids: &[String]) -> anyhow::Result<JsValue> {
    let credentials = JsArray::new();
    for cred_id in credential_ids {
        let id = Uint8Array::new_from_slice(&bin_decode(cred_id)?);

        let object = JsObject::new();
        JsReflect::set(
            &object,
            &JsValue::from_str("type"),
            &JsValue::from_str("public-key"),
        )
        .unwrap();
        JsReflect::set(&object, &JsValue::from_str("id"), &id).unwrap();

        credentials.push(&object);
    }

    Ok(JsValue::from(credentials))
}

fn encode_prf_salt(value: Vec<String>) -> Uint8Array {
    Uint8Array::new_from_slice(&sha256_raw(&value))
}

pub fn build_prf_eval_values(
    configs: &[PrfDeriveConfig],
) -> JsObject<AuthenticationExtensionsPrfValues> {
    let output: JsObject<AuthenticationExtensionsPrfValues> = JsObject::new_typed();
    for config in configs.iter() {
        let (first, second) = config.get_salts();
        let prf_value =
            AuthenticationExtensionsPrfValues::new_with_u8_array(&encode_prf_salt(first));
        prf_value.set_second_u8_array(&encode_prf_salt(second));

        JsReflect::set(&output, &JsValue::from_str(&config.cred_id), &prf_value).unwrap();
    }

    output
}

pub fn build_credential_request_extensions(
    prf_values: Option<JsObject<AuthenticationExtensionsPrfValues>>,
) -> AuthenticationExtensionsClientInputs {
    let prf_extension = AuthenticationExtensionsPrfInputs::new();
    if let Some(prf_values) = prf_values {
        prf_extension.set_eval_by_credential(&prf_values);
    }

    let extensions = AuthenticationExtensionsClientInputs::new();
    extensions.set_prf(&prf_extension);

    extensions
}
