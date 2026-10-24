use serde::{Deserialize, Serialize};
use std::cmp::PartialEq;
use strum::{Display, EnumString};
use ts_rs::TS;
use tsify::Tsify;
use wasm_bindgen::prelude::wasm_bindgen;

#[wasm_bindgen(skip_typescript)]
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize, EnumString, Display, Tsify, TS)]
#[tsify(namespace)]
pub enum EncryptionAlgorithm {
    ECC,    // X25519
    KEM,    // ML-KEM-768
    Hybrid, // Encrypts with both algorithms
}

#[wasm_bindgen(skip_typescript)]
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize, EnumString, Display, Tsify, TS)]
#[tsify(namespace)]
pub enum UserLevel {
    Admin,
    Standard,
    Machine,
}

#[wasm_bindgen(skip_typescript)]
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize, EnumString, Display, Tsify, TS)]
#[tsify(namespace)]
pub enum SecretDataType {
    Text,
    Json,
    Url,
}

#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Serialize,
    Deserialize,
    EnumString,
    Display,
    Tsify,
    TS,
    sqlx::Type,
)]
#[tsify(namespace)]
#[sqlx(type_name = r#""ChallengeKind""#)]
pub enum ChallengeKind {
    EmailSignup,
    EmailSignIn,
    PasskeySignup,
    PasskeySignIn,
    PasskeyAuthorize,
}

impl ChallengeKind {
    pub fn is_cloud_only(&self) -> bool {
        *self != ChallengeKind::PasskeyAuthorize
    }

    pub fn is_checkable(&self) -> bool {
        *self == ChallengeKind::EmailSignup || *self == ChallengeKind::EmailSignIn
    }

    pub fn is_new_user_only(&self) -> bool {
        *self == ChallengeKind::EmailSignup || *self == ChallengeKind::PasskeySignup
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize, EnumString, Display, Tsify, TS)]
#[tsify(namespace)]
pub enum AccessGrant {
    Pending,
    Granted,
}

#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Serialize,
    Deserialize,
    EnumString,
    Display,
    Tsify,
    TS,
    sqlx::Type,
)]
#[tsify(namespace)]
#[sqlx(type_name = r#""PasskeyType""#)]
pub enum PasskeyType {
    Local,
    Cloud,
}

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize, EnumString, Display, Tsify, TS)]
#[tsify(namespace)]
pub enum OperationMode {
    Local,
    Cloud,
}
