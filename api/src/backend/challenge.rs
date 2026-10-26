use crate::ApiState;
use crate::api_types::HttpError;
use crate::utils::error_mapper;
use axum::http::StatusCode;
use chrono::{DateTime, Utc};
use rand::RngExt;
use secretpass_core::enums::ChallengeKind;
use secretpass_core::utils::{bin_encode, fill_random_bytes, get_global_rng, sha256_digest};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use ts_rs::TS;

const CODE_POOL: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZ23456789";

#[derive(Debug, Clone, Deserialize, Serialize, TS)]
#[ts(export)]
pub struct CheckChallengeResult {
    pub valid: bool,
    pub attempts_left: i32,
}

#[derive(Debug, Clone, Deserialize, FromRow)]
pub struct PendingChallenge {
    pub owner: String,
    pub kind: ChallengeKind,
    pub value_hash: String,
    pub generated_on: DateTime<Utc>,
    pub attempts_left: i32,
}

impl PendingChallenge {
    pub(crate) async fn generate_webauthn(
        kind: ChallengeKind,
        owner: String,
    ) -> anyhow::Result<(String, Self)> {
        let mut challenge = [0u8; 32];
        fill_random_bytes(&mut challenge);
        let value = bin_encode(&challenge);
        let digest_value = value.clone();
        let value_hash = sha256_digest(&[digest_value]);

        let pc = Self {
            kind,
            owner,
            value_hash,
            generated_on: Utc::now(),
            attempts_left: 1,
        };

        Ok((value, pc))
    }

    pub(crate) async fn send_email_code(
        kind: ChallengeKind,
        owner: String,
        _is_proxied: bool,
    ) -> anyhow::Result<(String, Self)> {
        let mut rng = get_global_rng().lock().unwrap();
        let code: String = (0..6)
            .map(|_| {
                let idx = rng.random_range(0..CODE_POOL.len());
                CODE_POOL[idx] as char
            })
            .collect();

        if cfg!(debug_assertions) {
            println!("======================= EMAIL CODE =======================");
            println!(" * Code: {}", code);
            println!(" * Recipient: {}", owner);
            println!("==========================================================");
        } else {
            return Err(anyhow::anyhow!("Sending email code not yet supported"));
        }

        let value_hash = sha256_digest(&[code]);

        let pc = Self {
            kind,
            owner,
            value_hash,
            generated_on: Utc::now(),
            attempts_left: 4,
        };

        Ok(("Sent".to_string(), pc))
    }

    pub fn verify_challenge(&self, value: String) -> bool {
        let hash = sha256_digest(&[value]);

        hash == self.value_hash
    }

    pub(crate) async fn record(&self, state: &ApiState) -> Result<(), HttpError> {
        state
            .backend
            .record_pending_challenge(self)
            .await
            .map_err(error_mapper(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Error recording pending challenge",
            ))
    }
}
