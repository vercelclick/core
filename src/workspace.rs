use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use ts_rs::TS;
use uuid::Uuid;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, TS)]
pub struct Workspace {
    pub id: Uuid, // Fixed - invalidates keys if changed
    pub name: String,
    pub description: String,
    pub created_at: DateTime<Utc>,
}
