use serde::{Deserialize, Serialize};
use std::cmp::PartialEq;
use strum::{Display, EnumString};
use ts_rs::TS;

#[derive(
    Debug, Clone, Copy, PartialEq, Serialize, Deserialize, EnumString, Display, TS, sqlx::Type,
)]
#[sqlx(type_name = r#""ContributorRole""#)]
pub enum ContributorRole {
    Admin,
    Standard,
}

#[derive(
    Debug, Clone, Copy, PartialEq, Serialize, Deserialize, EnumString, Display, TS, sqlx::Type,
)]
#[sqlx(type_name = r#""EnvironmentAccessLevel""#)]
pub enum EnvironmentAccessLevel {
    ReadOnly,
    ReadWrite,
}

#[derive(
    Debug, Clone, Copy, PartialEq, Serialize, Deserialize, EnumString, Display, TS, sqlx::Type,
)]
#[sqlx(type_name = r#""SecretDataType""#)]
pub enum SecretDataType {
    Text,
    Json,
    Url,
}

#[derive(
    Debug, Clone, Copy, PartialEq, Serialize, Deserialize, EnumString, Display, TS, sqlx::Type,
)]
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
    Debug, Clone, Copy, PartialEq, Serialize, Deserialize, EnumString, Display, TS, sqlx::Type,
)]
#[sqlx(type_name = r#""AccessGrant""#)]
pub enum AccessGrant {
    Pending,
    Granted,
}

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize, EnumString, Display, TS)]
pub enum OperationMode {
    Local,
    Cloud,
}

#[derive(
    Debug, Clone, Copy, PartialEq, Serialize, Deserialize, EnumString, Display, TS, sqlx::Type,
)]
#[sqlx(type_name = r#""ContributorStatus""#)]
pub enum ContributorStatus {
    Active,
    Archived,
}
