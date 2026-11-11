use chrono::{DateTime, Utc};
use secretpass_core::enums::ChallengeKind;
use secretpass_core::utils::{bin_encode, fill_random_bytes, sha256_digest};
use serde::Deserialize;
use sqlx::FromRow;

#[cfg(feature = "cloud")]
const CODE_POOL: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZ23456789";

#[derive(Debug, Clone, Deserialize, FromRow)]
pub struct PendingChallenge {
    pub owner: String,
    pub kind: ChallengeKind,
    pub value_hash: String,
    pub generated_on: DateTime<Utc>,
    pub attempts_left: i32,
}

impl PendingChallenge {
    pub(crate) fn generate_webauthn(kind: ChallengeKind, owner: String) -> (String, Self) {
        let mut challenge = [0u8; 32];
        fill_random_bytes(&mut challenge);
        let value = bin_encode(&challenge);
        let value_hash = sha256_digest(std::slice::from_ref(&value));

        let pc = Self {
            kind,
            owner,
            value_hash,
            generated_on: Utc::now(),
            attempts_left: 1,
        };

        (value, pc)
    }

    #[cfg(feature = "cloud")]
    pub fn generate_email_code(kind: ChallengeKind, owner: String) -> (String, Self) {
        use rand::RngExt;
        use secretpass_core::utils::get_global_rng;

        let code = {
            let mut rng = get_global_rng().lock().unwrap();
            let code: String = (0..6)
                .map(|_| {
                    let idx = rng.random_range(0..CODE_POOL.len());
                    CODE_POOL[idx] as char
                })
                .collect();
            code
        };

        let value_hash = sha256_digest(std::slice::from_ref(&code));

        let pending_challenge = Self {
            kind,
            owner,
            value_hash,
            generated_on: Utc::now(),
            attempts_left: 4,
        };

        (code, pending_challenge)
    }

    pub fn verify_challenge(&self, value: String) -> bool {
        let hash = sha256_digest(&[value]);

        hash == self.value_hash
    }
}
