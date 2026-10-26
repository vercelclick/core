use serde::{Deserialize, Serialize};
use std::cmp::PartialEq;
use strum::{Display, EnumString};
use ts_rs::TS;
use tsify::Tsify;
use wasm_bindgen::prelude::wasm_bindgen;

#[wasm_bindgen(skip_typescript)]
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
#[sqlx(type_name = r#""EncryptionAlgorithm""#)]
pub enum EncryptionAlgorithm {
    ECC,    // X25519
    KEM,    // ML-KEM-768
    Hybrid, // Encrypts with both algorithms
}

impl EncryptionAlgorithm {
    pub fn is_ecc(&self) -> bool {
        *self == EncryptionAlgorithm::ECC || *self == EncryptionAlgorithm::Hybrid
    }

    pub fn is_kem(&self) -> bool {
        *self == EncryptionAlgorithm::KEM || *self == EncryptionAlgorithm::Hybrid
    }
}

#[wasm_bindgen(skip_typescript)]
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
#[sqlx(type_name = r#""ProjectUserLevel""#)]
pub enum ProjectUserLevel {
    Admin,
    Standard,
}

#[wasm_bindgen(skip_typescript)]
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
#[sqlx(type_name = r#""SecretDataType""#)]
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
    PasskeyCreate,
    EmailAuthorize,
}

impl ChallengeKind {
    pub fn is_cloud_only(&self) -> bool {
        *self != ChallengeKind::PasskeyAuthorize
    }

    pub fn is_checkable(&self) -> bool {
        *self == ChallengeKind::EmailSignup
            || *self == ChallengeKind::EmailSignIn
            || *self == ChallengeKind::EmailAuthorize
    }

    pub fn is_new_user_only(&self) -> bool {
        *self == ChallengeKind::EmailSignup || *self == ChallengeKind::PasskeySignup
    }
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
#[sqlx(type_name = r#""AccessGrant""#)]
pub enum AccessGrant {
    Pending,
    Granted,
}

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize, EnumString, Display, Tsify, TS)]
#[tsify(namespace)]
pub enum OperationMode {
    Local,
    Cloud,
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
#[sqlx(type_name = r#""ProjectUserStatus""#)]
pub enum ProjectUserStatus {
    Active,
    Archived,
}
