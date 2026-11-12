use crate::enums::{EmailChallengeKind, WebauthnChallengeKind};
use crate::utils::{bin_encode, fill_random_bytes, get_global_rng, sha256_digest};
use chrono::{DateTime, Utc};
use rand::RngExt;
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use ts_rs::TS;

const CODE_POOL: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZ23456789";

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, TS, FromRow)]
pub struct EmailChallenge {
    pub owner: String,
    pub kind: EmailChallengeKind,
    pub value_hash: String,
    pub expires_on: DateTime<Utc>,
    pub attempts_left: i32,
}

impl EmailChallenge {
    pub fn generate() -> (String, String) {
        let mut rng = get_global_rng().lock().unwrap();
        let code: String = (0..6)
            .map(|_| {
                let idx = rng.random_range(0..CODE_POOL.len());
                CODE_POOL[idx] as char
            })
            .collect();

        let value_hash = sha256_digest(std::slice::from_ref(&code));
        (code, value_hash)
    }

    pub fn validate(&self, code: &str) -> bool {
        self.value_hash == sha256_digest(&[code])
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, TS, FromRow)]
pub struct WebauthnChallenge {
    pub owner: String,
    pub kind: WebauthnChallengeKind,
    pub value_hash: String,
    pub expires_on: DateTime<Utc>,
}

impl WebauthnChallenge {
    pub fn generate() -> (String, String) {
        let mut challenge = [0u8; 32];
        fill_random_bytes(&mut challenge);
        let value = bin_encode(&challenge);
        let value_hash = sha256_digest(std::slice::from_ref(&value));

        (value, value_hash)
    }
}
