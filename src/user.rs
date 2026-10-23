use crate::UserLevel;
use crate::lock::HashedLock;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use ts_rs::TS;
use tsify::Tsify;
use uuid::Uuid;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Tsify, TS)]
pub struct SecretpassUser {
    pub id: Uuid,
    pub email: String, // Fixed - invalidates keys if changed
    pub name: String,
    pub created_at: DateTime<Utc>, // Fixed - invalidates keys if changed
}

impl HashedLock for SecretpassUser {
    fn salt(&self) -> Vec<String> {
        vec![
            self.id.to_string(),
            self.email.clone(),
            self.created_at.to_rfc3339(),
        ]
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Tsify, TS)]
pub struct SecretpassProjectUser {
    pub id: Uuid,
    pub user_id: Uuid,
    pub project_id: Uuid,
    pub level: UserLevel,
    pub environments: Vec<String>,
    pub created_at: DateTime<Utc>,
}

impl HashedLock for SecretpassProjectUser {
    fn salt(&self) -> Vec<String> {
        vec![
            self.id.to_string(),
            self.user_id.to_string(),
            self.project_id.to_string(),
            self.created_at.to_rfc3339(),
        ]
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Tsify, TS)]
pub struct SecretpassUserSession {
    pub id: Uuid,
    pub user_id: Uuid,
    pub last_seen: DateTime<Utc>,
    pub created_on: DateTime<Utc>,
    pub expires_on: DateTime<Utc>,
}
