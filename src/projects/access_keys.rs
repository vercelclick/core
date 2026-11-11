use crate::constants::FEDERATED_ACCESS_KEY_LENGTH;
use crate::projects::EnvironmentAccess;
use crate::utils::{bin_decode, bin_encode};
use crate::{InternalError, InternalResult};
use chrono::{DateTime, Utc};
use http::StatusCode;
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use ts_rs::TS;
use uuid::Uuid;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, TS, FromRow)]
pub struct AccessKey {
    pub id: Uuid,
    pub name: String,
    pub description: String,
    pub project_id: Uuid,
    pub access: Vec<EnvironmentAccess>,
    pub public_key: String,
    pub generated_by: String, // Set to the email of the generator
    pub generated_on: DateTime<Utc>,
}

impl AccessKey {
    pub fn get_access(&self, env_name: &str) -> Option<EnvironmentAccess> {
        self.access
            .iter()
            .find(|access| access.name == env_name)
            .cloned()
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, TS, FromRow)]
pub struct FederatedAccessKey {
    pub id: Uuid,
    pub name: String,
    pub description: String,
    pub project_id: Uuid,
    pub access: Vec<EnvironmentAccess>,
    pub contributors: Vec<Uuid>,
    pub generated_by: String, // Set to the email of the generator
    pub generated_on: DateTime<Utc>,
}

impl FederatedAccessKey {
    pub fn encode_key(&self) -> String {
        let id: [u8; 16] = self.id.into_bytes();
        let project_id: [u8; 16] = self.project_id.into_bytes();
        let key = [&id[..], &project_id[..]];
        let key: Vec<u8> = key.concat();
        bin_encode(&key)
    }

    pub fn parse_key(key: &str) -> InternalResult<(Uuid, Uuid)> {
        let key = bin_decode(key)?;

        if key.len() != FEDERATED_ACCESS_KEY_LENGTH {
            return Err(InternalError::new(
                StatusCode::BAD_REQUEST,
                "Invalid federated access key format",
            ));
        }

        let id = &key[..16];
        let project_id = &key[16..];

        let id = Uuid::from_bytes(id.try_into().map_err(|err| {
            InternalError::trace(
                StatusCode::BAD_REQUEST,
                "Invalid federal access key ID",
                err,
            )
        })?);
        let project_id = Uuid::from_bytes(project_id.try_into().map_err(|err| {
            InternalError::trace(StatusCode::BAD_REQUEST, "Invalid project ID", err)
        })?);

        Ok((id, project_id))
    }
}
