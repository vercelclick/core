use crate::backend::challenge::{get_pending_challenge, save_pending_challenge};
use secretpass_api::{BackendProvider, PendingChallenge};
use secretpass_core::enums::ChallengeKind;

pub struct LocalBackendProvider {}

#[async_trait::async_trait]
impl BackendProvider for LocalBackendProvider {
    async fn pending_challenge_record(&self, challenge: PendingChallenge) -> anyhow::Result<()> {
        save_pending_challenge(challenge).await;
        Ok(())
    }

    async fn pending_challenge_retrieve(
        &mut self,
        kind: ChallengeKind,
        challenge: String,
    ) -> anyhow::Result<String> {
        get_pending_challenge(kind, challenge)
            .await
            .ok_or_else(Err(anyhow::anyhow!("Pending challenge not found")))
    }
}
