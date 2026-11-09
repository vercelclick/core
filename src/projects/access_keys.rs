use crate::projects::EnvironmentAccess;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use ts_rs::TS;
use tsify::Tsify;
use uuid::Uuid;
use wasm_bindgen::prelude::wasm_bindgen;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Tsify, TS, FromRow)]
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

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Tsify, TS, FromRow)]
pub struct FederatedAccessKey {
    pub id: Uuid,
    pub name: String,
    pub description: String,
    pub project_id: Uuid,
    pub access: Vec<EnvironmentAccess>,
    pub users: Vec<Uuid>,
    pub generated_by: String, // Set to the email of the generator
    pub generated_on: DateTime<Utc>,
}
