use crate::enums::{ContributorRole, ContributorStatus};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use ts_rs::TS;
use tsify::Tsify;
use uuid::Uuid;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Tsify, TS, FromRow)]
pub struct SpassContributor {
    pub id: Uuid,
    pub user_id: Uuid,
    pub status: ContributorStatus,
    pub project_id: Uuid,
    pub role: ContributorRole,
    pub environments: Vec<String>,
    pub updated_at: DateTime<Utc>,
}

impl SpassContributor {
    pub fn can_access(&self, env_name: &String) -> bool {
        if self.role == ContributorRole::Admin {
            true
        } else {
            self.environments.contains(env_name)
        }
    }
}
