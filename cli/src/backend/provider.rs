use crate::backend::challenge::{get_pending_challenge, save_pending_challenge};
use secretpass_api::{BackendProvider, PendingChallenge};
use secretpass_core::enums::ChallengeKind;

pub struct LocalBackendProvider {
    support: bool,
}

impl LocalBackendProvider {
    pub fn new(support: bool) -> Self {
        Self { support }
    }
}

#[async_trait::async_trait]
impl BackendProvider for LocalBackendProvider {
    async fn pending_challenge_record(&self, challenge: PendingChallenge) -> anyhow::Result<()> {
        save_pending_challenge(challenge).await;
        Ok(())
    }

    async fn pending_challenge_retrieve(
        &self,
        kind: ChallengeKind,
        challenge: String,
    ) -> anyhow::Result<PendingChallenge> {
        get_pending_challenge(kind, challenge)
            .await
            .ok_or_else(|| anyhow::anyhow!("Pending challenge not found"))
    }

    async fn projects_list(&self) -> anyhow::Result<()> {
        todo!()
    }

    async fn projects_get(&self, _id: &str) -> anyhow::Result<()> {
        todo!()
    }

    async fn workspaces_list(&self) -> anyhow::Result<()> {
        todo!()
    }
}
