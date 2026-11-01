use secretpass_core::passkeys::authorize::PasskeyAuthorizationResult;
use secretpass_core::{ContributorUpdateValue, MachineUpdateValue};
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
    pub contributors_values: Vec<ContributorUpdateValue>,
    pub machines_values: Vec<MachineUpdateValue>,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct GetMachineSecretParams {
    pub env_name: String,
    pub project_id: Uuid,
    pub tag: String,
    pub key_a: String,
    pub key_b: String,
    pub key_c: String,
}
