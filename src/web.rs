/**
* Web package specific types that are shared with the rest of the packages
*/
use serde::{Deserialize, Serialize};
use ts_rs::TS;
use tsify::Tsify;
use uuid::Uuid;
use wasm_bindgen::prelude::wasm_bindgen;

#[derive(Debug, Clone, Serialize, Deserialize, Tsify, TS)]
pub struct EncryptedContributorValue {
    pub target: Uuid,
    pub encrypted_value: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Tsify, TS)]
pub struct EncryptedMachineValue {
    pub target: String,
    pub encrypted_value: String,
}
