use crate::enums::PasskeyType;
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use ts_rs::TS;
use tsify::Tsify;
use uuid::Uuid;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Tsify, TS, FromRow)]
pub struct SpassPasskey {
    pub id: Uuid, // Credential ID
    pub user_id: Uuid,
    pub name: String,
    pub cred_id: String, // Base64url-encoded credential id
    #[serde(rename = "type")]
    #[sqlx(rename = "type")]
    pub type_: PasskeyType,
    pub public_key: String, // Base64url-encoded COSE key
    pub ecc: String,
    pub kem: String,
}
