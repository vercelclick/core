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
#[sqlx(type_name = r#""EmailChallengeKind""#)]
pub enum EmailChallengeKind {
    EmailSignup,
    EmailSignIn,
    EmailAuthorize,
}

#[derive(
    Debug, Clone, Copy, PartialEq, Serialize, Deserialize, EnumString, Display, TS, sqlx::Type,
)]
#[sqlx(type_name = r#""WebauthnChallengeKind""#)]
pub enum WebauthnChallengeKind {
    PasskeySignup,
    PasskeySignIn,
    PasskeyCreate,
    PasskeyAuthorize,
}

impl WebauthnChallengeKind {
    pub fn is_cloud_only(&self) -> bool {
        *self != Self::PasskeyAuthorize
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

#[derive(
    Debug, Clone, Copy, PartialEq, Serialize, Deserialize, EnumString, Display, TS, sqlx::Type,
)]
#[sqlx(type_name = r#""ContributorStatus""#)]
pub enum ContributorStatus {
    Active,
    Archived,
}
