use chrono::{DateTime, Utc};
use rand::RngExt;
use secretpass_core::enums::ChallengeKind;
use secretpass_core::utils::{bin_encode, fill_random_bytes, sha256_digest};
use serde::Deserialize;
use sqlx::FromRow;

const CODE_POOL: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZ23456789";

#[derive(Debug, Clone, Deserialize, FromRow)]
pub struct PendingChallenge {
    pub owner: String,
    pub kind: ChallengeKind,
    pub value_hash: String,
    pub generated_on: DateTime<Utc>,
}

impl PendingChallenge {
    pub(crate) async fn generate_webauthn(
        kind: ChallengeKind,
        owner: String,
    ) -> anyhow::Result<(String, Self)> {
        let mut challenge = [0u8; 32];
        fill_random_bytes(&mut challenge);
        let value = bin_encode(&challenge);
        let value_hash = sha256_digest(&[value.clone()]);

        let pc = Self {
            kind,
            owner,
            value_hash,
            generated_on: Utc::now(),
        };

        Ok((value, pc))
    }

    pub(crate) async fn send_email_code(
        kind: ChallengeKind,
        owner: String,
    ) -> anyhow::Result<(String, Self)> {
        let mut rng = rand::rng();
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

        let value_hash = sha256_digest(&[code.clone()]);

        let pc = Self {
            kind,
            owner,
            value_hash,
            generated_on: Utc::now(),
        };

        Ok(("Sent".to_string(), pc))
    }

    pub fn verify_challenge(&self, value: String) -> bool {
        let hash = sha256_digest(&[value]);

        hash == self.value_hash
    }
}
