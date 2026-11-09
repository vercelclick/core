use secretpass_core::utils::{bin_encode, fill_random_bytes};
use wasm_bindgen::prelude::wasm_bindgen;

#[wasm_bindgen]
pub fn generate_salt() -> String {
    let mut key_bytes = [0u8; 32];
    fill_random_bytes(&mut key_bytes);

    bin_encode(&key_bytes)
}
