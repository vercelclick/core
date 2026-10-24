use crate::enums::EncryptionAlgorithm;
use crate::lock::HashedLock;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use ts_rs::TS;
use tsify::Tsify;
use uuid::Uuid;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Tsify, TS)]
pub struct SecretpassProject {
    pub id: Uuid, // Fixed - invalidates keys if changed - uuid v4 local, uuid v7 cloud
    pub name: String,
    pub description: String,
    pub algorithm: EncryptionAlgorithm, // Fixed - invalidates keys if changed
    pub created_at: DateTime<Utc>,      // Fixed - invalidates keys if changed
    pub workspace_id: Option<Uuid>,
}

impl HashedLock for SecretpassProject {
    fn salt(&self) -> Vec<String> {
        let mut salt = vec![
            self.id.to_string(),
            self.algorithm.to_string(),
            self.created_at.to_rfc3339(),
        ];
        if let Some(workspace_id) = &self.workspace_id {
            salt.push(workspace_id.to_string());
        }

        salt
    }
}
