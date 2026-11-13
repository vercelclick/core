use crate::Passkey;
use crate::users::user::User;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use ts_rs::TS;
use uuid::Uuid;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, TS, FromRow)]
pub struct Session {
    pub id: Uuid,
    pub user_id: Uuid,
    pub last_seen: DateTime<Utc>,
    pub expires_on: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct AuthSession {
    pub id: Uuid,
    pub user: User,
    pub passkeys: Vec<Passkey>,
}
