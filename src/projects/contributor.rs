use crate::constants::ENVIRONMENT_ALL_ACCESS;
use crate::enums::{AccessGrant, ContributorRole, ContributorStatus, EnvironmentAccessLevel};
use crate::projects::EnvironmentAccess;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use ts_rs::TS;
use uuid::Uuid;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, TS, FromRow)]
pub struct Contributor {
    pub id: Uuid,
    pub user_id: Uuid,
    pub status: ContributorStatus,
    pub project_id: Uuid,
    pub role: ContributorRole,
    pub access: Vec<EnvironmentAccess>,
    pub updated_at: DateTime<Utc>,
}

impl Contributor {
    pub fn is_admin(&self) -> bool {
        self.role == ContributorRole::Admin
    }

    pub fn get_access(&self, env_name: &str) -> Option<EnvironmentAccess> {
        if self.is_admin() {
            return Some(EnvironmentAccess {
                name: env_name.to_string(),
                secrets: vec![ENVIRONMENT_ALL_ACCESS.to_string()],
                level: EnvironmentAccessLevel::ReadWrite,
            });
        };

        self.access
            .iter()
            .find(|access| access.name == env_name)
            .cloned()
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, TS, FromRow)]
pub struct ContributorPublicKey {
    pub id: Uuid,
    pub name: String,
    pub user_id: Uuid,
    pub cred_id: String,
    pub access: AccessGrant,
    pub user_salt: String,
    pub passkey_salt: String,
    pub public_key: String,
    pub contributor_id: Uuid,
    pub granted_by: Option<String>,
    pub granted_on: Option<DateTime<Utc>>,
}
