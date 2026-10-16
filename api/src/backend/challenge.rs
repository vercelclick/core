use chrono::{DateTime, Utc};
use secretpass_core::enums::ChallengeKind;
use secretpass_core::utils::{bin_decode, bin_encode, fill_random_bytes};
use serde::Deserialize;
use sqlx::FromRow;

#[derive(Debug, Clone, Deserialize, FromRow)]
pub struct PendingChallenge {
    pub owner: String,
    pub kind: ChallengeKind,
    pub value: String,
    pub generated_on: DateTime<Utc>,
}

impl PendingChallenge {
    pub fn generate(owner: String, kind: ChallengeKind) -> Self {
        let mut challenge = [0u8; 32];
        fill_random_bytes(&mut challenge);
        let value = bin_encode(&challenge);

        Self {
            owner,
            kind,
            value,
            generated_on: Utc::now(),
        }
    }

    pub fn challenge(&self) -> anyhow::Result<[u8; 32]> {
        let bin = bin_decode(&self.value)?;

        let bytes: [u8; 32] = bin.as_slice().try_into()?;
        Ok(bytes)
    }
}
