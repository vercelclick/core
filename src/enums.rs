use serde::{Deserialize, Serialize};
use strum::{Display, EnumString};
use tsify::Tsify;
use wasm_bindgen::prelude::wasm_bindgen;

#[wasm_bindgen(skip_typescript)]
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize, EnumString, Display, Tsify)]
#[tsify(namespace)]
pub enum EncryptionAlgorithm {
    ECC,    // X25519
    KEM,    // ML-KEM-768
    Hybrid, // Encrypts with both algorithms
}

#[wasm_bindgen(skip_typescript)]
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize, EnumString, Display, Tsify)]
#[tsify(namespace)]
pub enum UserLevel {
    Admin,
    Standard,
    Machine,
}

#[wasm_bindgen(skip_typescript)]
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize, EnumString, Display, Tsify)]
#[tsify(namespace)]
pub enum SecretDataType {
    Text,
    Json,
    Url,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, EnumString, Display, Tsify)]
#[tsify(namespace)]
pub enum ChallengeKind {
    WebauthUser,
    WebauthPasskey,
    EmailSignup,
    EmailSignIn,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, EnumString, Display, Tsify)]
#[tsify(namespace)]
pub enum AccessGrant {
    Pending,
    Granted,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, EnumString, Display, Tsify)]
#[tsify(namespace)]
pub enum PasskeyType {
    Local,
    Cloud,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, EnumString, Display, Tsify)]
#[tsify(namespace)]
pub enum OperationMode {
    Local,
    Cloud,
}
