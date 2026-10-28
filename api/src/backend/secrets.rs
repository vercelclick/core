use secretpass_web::{EncryptedMachineValue, EncryptedUserValue, PasskeyAuthorizationResult};
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
    pub user_values: Vec<EncryptedUserValue>,
    pub machine_values: Vec<EncryptedMachineValue>,
}
