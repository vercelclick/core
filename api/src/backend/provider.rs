use crate::auth::BackendCreateUserRequest;
use crate::backend::auth::SessionPackage;
use crate::backend::challenge::PendingChallenge;
use crate::projects::ListProjectsResult;
use secretpass_core::enums::{ChallengeKind, PasskeyType};
use secretpass_core::{SecretpassPasskey, SecretpassUser};
use uuid::Uuid;

#[async_trait::async_trait]
pub trait BackendProvider: Send + Sync + 'static {
    async fn record_pending_challenge(&self, challenge: &PendingChallenge) -> anyhow::Result<()>;

    async fn retrieve_pending_challenge_for_attempt(
        &self,
        kind: ChallengeKind,
        owner: String,
    ) -> anyhow::Result<Option<PendingChallenge>>;

    async fn pop_pending_challenge(
        &self,
        kind: ChallengeKind,
        owner: String,
    ) -> anyhow::Result<Option<PendingChallenge>>;

    async fn create_user(
        &self,
        request: BackendCreateUserRequest,
    ) -> anyhow::Result<SessionPackage>;

    // Only called for local
    async fn record_session(&self, response: SessionPackage) -> anyhow::Result<()>;

    async fn get_session(
        &self,
        passkey_type: PasskeyType,
        id: Uuid,
    ) -> anyhow::Result<Option<SessionPackage>>;

    async fn create_session_by_email(
        &self,
        passkey_type: PasskeyType,
        email: String,
    ) -> anyhow::Result<SessionPackage>;

    async fn get_user_email(&self, email: String) -> anyhow::Result<Option<(i32, SecretpassUser)>>;

    async fn create_session_by_user_id(
        &self,
        passkey_type: PasskeyType,
        user_id: Uuid,
    ) -> anyhow::Result<SessionPackage>;

    async fn retrieve_user_id_and_public_key(
        &self,
        passkey_type: PasskeyType,
        cred_id: String,
    ) -> anyhow::Result<Option<(Uuid, String)>>;

    async fn retrieve_user_and_known_passkeys(
        &self,
        email: String,
        passkey_type: PasskeyType,
    ) -> anyhow::Result<Option<(SecretpassUser, Vec<SecretpassPasskey>)>>;

    async fn list_projects(&self, user: &SecretpassUser) -> anyhow::Result<ListProjectsResult>;
}
