use secretpass_core::passkeys::authorize::PasskeyAuthorizationResult;
use secretpass_core::{EnvironmentAccess, SecretValue};
use serde::{Deserialize, Serialize};
use ts_rs::TS;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct ProjectEnvPathParams {
    pub env_name: String,
    pub project_id: Uuid,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct ProjectSecretPathParams {
    pub env_name: String,
    pub project_id: Uuid,
    pub secret_name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct ProjectPathParams {
    pub project_id: Uuid,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct CreateSecretRequest {
    pub name: String,
    pub comments: String,
    pub auth_result: PasskeyAuthorizationResult,
    pub encrypted_values: Vec<SecretValue>,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct UpdateSecretValueRequest {
    pub auth_result: PasskeyAuthorizationResult,
    pub encrypted_values: Vec<SecretValue>,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct UpdateSecretRequest {
    pub comments: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct ProjectAccessKeyParams {
    pub project_id: Uuid,
    pub env_name: String,
    pub tag_name: String,
    pub key_id: Uuid,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct CreateAccessKeyRequest {
    pub id: Uuid,
    pub name: String,
    pub description: String,
    pub access: Vec<EnvironmentAccess>,
    pub auth_result: PasskeyAuthorizationResult,
    pub public_key: String,
    pub encrypted_values: Vec<SecretValue>,
}
