use crate::backend::{challenge::PendingChallenge, config::BackendConfig};
use secretpass_core::enums::ChallengeKind;

#[async_trait::async_trait]
pub trait BackendProvider: Send + Sync + 'static {
    // Return the challenge to be used for authentication of a specific user
    // The challenge must be stored to be retrieved later for
    async fn pending_challenge_record(&self, challenge: PendingChallenge) -> anyhow::Result<()>;

    // Should return the user's email address given the challenge
    async fn pending_challenge_retrieve(
        &self,
        kind: ChallengeKind,
        challenge: String,
    ) -> anyhow::Result<PendingChallenge>;

    async fn config(&self) -> anyhow::Result<BackendConfig>;

    async fn projects_list(&self) -> anyhow::Result<()>;

    // Get a project by ID
    async fn projects_get(&self, id: &str) -> anyhow::Result<()>;

    async fn workspaces_list(&self) -> anyhow::Result<()>;
}
