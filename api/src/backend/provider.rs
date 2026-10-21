use crate::backend::auth::{CreateUserParams, SessionResponse};
use crate::backend::challenge::PendingChallenge;
use secretpass_core::enums::ChallengeKind;
use secretpass_core::{SecretpassUser, SecretpassUserSession};

#[async_trait::async_trait]
pub trait BackendProvider: Send + Sync + 'static {
    // Return the challenge to be used for authentication of a specific user
    // The challenge must be stored to be retrieved later for
    async fn pending_challenge_record(&self, challenge: PendingChallenge) -> anyhow::Result<()>;

    // Should return the user's email address given the challenge
    async fn pending_challenge_retrieve(
        &self,
        kind: ChallengeKind,
        owner: String,
    ) -> anyhow::Result<PendingChallenge>;

    async fn projects_list(&self) -> anyhow::Result<()>;

    // Get a project by ID
    async fn projects_get(&self, id: &str) -> anyhow::Result<()>;

    async fn workspaces_list(&self) -> anyhow::Result<()>;

    async fn create_user(&self, params: CreateUserParams) -> anyhow::Result<SessionResponse>;

    // Only called for local
    async fn record_session(
        &self,
        user: SecretpassUser,
        session: SecretpassUserSession,
    ) -> anyhow::Result<()>;

    async fn get_session(&self, id: String) -> anyhow::Result<Option<SessionResponse>>;
}
