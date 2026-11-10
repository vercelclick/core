use secretpass_core::{InternalError, InternalResult, StatusCode};
use wasm_bindgen::JsCast;
use web_sys::js_sys::Promise;
use web_sys::{CredentialsContainer, PublicKeyCredential};

pub fn get_credentials_container() -> InternalResult<CredentialsContainer> {
    let window = match web_sys::window() {
        Some(window) => window,
        None => {
            return Err(InternalError::new(
                StatusCode::BAD_GATEWAY,
                "Please run Secretpass in a supported browser",
            ));
        }
    };
    let navigator = window.navigator();

    Ok(navigator.credentials())
}

pub async fn parse_promise(promise: Promise) -> InternalResult<PublicKeyCredential> {
    let result = promise.await.map_err(|err| {
        InternalError::trace(
            StatusCode::UNAUTHORIZED,
            "Error processing passkey authentication result",
            err,
        )
    })?;
    let credential = result.dyn_into::<PublicKeyCredential>().map_err(|err| {
        InternalError::trace(
            StatusCode::UNAUTHORIZED,
            "Error parsing passkey authentication result",
            err,
        )
    })?;

    Ok(credential)
}
