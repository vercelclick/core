use secretpass_core::passkeys::authorize::PasskeyAuthorizationResult;
use secretpass_core::web::{EncryptedContributorValue, EncryptedMachineValue};
use serde::{Deserialize, Serialize};
use ts_rs::TS;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct CreateSecretParams {
    pub env_name: String,
    pub project_id: Uuid,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct CreateSecretRequest {
    pub name: String,
    pub comments: String,
    pub auth_result: PasskeyAuthorizationResult,
    pub contributors_values: Vec<EncryptedContributorValue>,
    pub machines_values: Vec<EncryptedMachineValue>,
}
