use crate::UserLevel;
use crate::lock::HashedLock;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use ts_rs::TS;
use tsify::Tsify;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Tsify, TS)]
pub struct SecretpassUser {
    pub id: String,    // Fixed - invalidates keys if changed, UUID v7
    pub email: String, // Fixed - invalidates keys if changed
    pub name: String,
    pub created_at: String, // Fixed - invalidates keys if changed
}

impl HashedLock for SecretpassUser {
    fn salt(&self) -> Vec<String> {
        vec![self.id.clone(), self.email.clone(), self.created_at.clone()]
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Tsify, TS)]
pub struct SecretpassProjectUser {
    pub id: String,
    pub user_id: String,
    pub project_id: String,
    pub level: UserLevel,
    pub environments: Vec<String>,
    pub created_at: String,
}

impl HashedLock for SecretpassProjectUser {
    fn salt(&self) -> Vec<String> {
        vec![
            self.id.clone(),
            self.user_id.clone(),
            self.project_id.clone(),
            self.created_at.clone(),
        ]
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Tsify, TS)]
pub struct SecretpassUserSession {
    pub id: String,
    pub user_id: String,
    pub last_seen: DateTime<Utc>,
    pub created_on: DateTime<Utc>,
    pub expires_on: DateTime<Utc>,
}
