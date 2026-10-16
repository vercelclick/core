use crate::backend::challenge::{get_pending_challenge, insert_or_replace_challenge};
use secretpass_api::{BackendProvider, PendingChallenge};
use secretpass_core::enums::ChallengeKind;
use sqlx::PgPool;
use std::sync::Arc;

pub struct CloudBackendProvider {
    pool: Arc<PgPool>,
}

impl CloudBackendProvider {
    pub fn new(pool: PgPool) -> Self {
        CloudBackendProvider {
            pool: Arc::new(pool),
        }
    }
}

#[async_trait::async_trait]
impl BackendProvider for CloudBackendProvider {
    async fn pending_challenge_record(
        &self,
        challenge: secretpass_api::PendingChallenge,
    ) -> anyhow::Result<()> {
        insert_or_replace_challenge(&self.pool, challenge).await
    }

    async fn pending_challenge_retrieve(
        &self,
        kind: ChallengeKind,
        challenge: String,
    ) -> anyhow::Result<PendingChallenge> {
        get_pending_challenge(&self.pool, kind, challenge).await
    }
}
