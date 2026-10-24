use crate::lock::HashedLock;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use ts_rs::TS;
use tsify::Tsify;
use uuid::Uuid;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Tsify, TS)]
pub struct SecretpassWorkspace {
    pub id: Uuid, // Fixed - invalidates keys if changed
    pub name: String,
    pub description: String,
    pub created_at: DateTime<Utc>,
}

impl HashedLock for SecretpassWorkspace {
    fn salt(&self) -> Vec<String> {
        vec![self.id.to_string(), self.created_at.to_rfc3339()]
    }
}
