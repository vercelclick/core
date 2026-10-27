use crate::enums::{ProjectUserLevel, ProjectUserStatus};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use ts_rs::TS;
use tsify::Tsify;
use uuid::Uuid;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Tsify, TS, FromRow)]
pub struct SpassProjectUser {
    pub id: Uuid,
    pub user_id: Uuid,
    pub status: ProjectUserStatus,
    pub project_id: Uuid,
    pub level: ProjectUserLevel,
    pub environments: Vec<String>,
    pub updated_at: DateTime<Utc>,
}

impl SpassProjectUser {
    pub fn can_access(&self, env_name: &String) -> bool {
        if self.level == ProjectUserLevel::Admin {
            true
        } else {
            self.environments.contains(env_name)
        }
    }
}
