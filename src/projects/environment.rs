use crate::constants::ENVIRONMENT_ALL_ACCESS;
use crate::enums::EnvironmentAccessLevel;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use ts_rs::TS;
use tsify::Tsify;
use uuid::Uuid;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Tsify, TS, FromRow)]
pub struct Environment {
    pub name: String,
    pub project_id: Uuid,
    pub description: String,
    pub tags: Vec<String>,
    pub updated_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>, // Fixed - invalidates keys if changed
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Tsify, TS, sqlx::Type)]
#[sqlx(type_name = r#""EnvironmentAccess""#)]
pub struct EnvironmentAccess {
    pub name: String,
    pub level: EnvironmentAccessLevel,
    pub secrets: Vec<String>,
}

impl EnvironmentAccess {
    pub fn can_write_secret(&self, secret_name: &String) -> bool {
        if self.level != EnvironmentAccessLevel::ReadWrite {
            return false;
        }

        self.is_all_access() || self.secrets.contains(secret_name)
    }

    pub fn can_read_secret(&self, secret_name: &String) -> bool {
        self.is_all_access() || self.secrets.contains(secret_name)
    }

    pub fn is_all_access(&self) -> bool {
        self.secrets.contains(&ENVIRONMENT_ALL_ACCESS.to_string())
    }

    pub fn is_env_admin(&self) -> bool {
        self.level == EnvironmentAccessLevel::ReadWrite && self.is_all_access()
    }
}
