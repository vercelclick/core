use crate::Passkey;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use ts_rs::TS;
use uuid::Uuid;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, TS, FromRow)]
pub struct User {
    pub id: Uuid,
    pub email: String,
    pub name: String,
    pub key_salt: String,
    pub updated_at: DateTime<Utc>,
}

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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthTokenClaims {
    pub sub: Uuid,
    pub iss: String,
    pub aud: String, // Audience
    pub exp: u64,
    pub iat: u64,

    // Custom claims
    pub user: User,
    pub passkeys: Vec<Passkey>,
}

impl AuthTokenClaims {
    pub fn make_session(self) -> AuthSession {
        AuthSession {
            id: self.sub,
            user: self.user,
            passkeys: self.passkeys,
        }
    }
}
