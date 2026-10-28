use crate::auth::BackendCreateUserRequest;
use crate::backend::auth::SessionPackage;
use crate::backend::challenge::PendingChallenge;
use crate::environments::{GetEnvironmentRequest, GetEnvironmentResult, SecretWithEncryptedValues};
use crate::projects::{CreateProjectRequest, GetProjectResult, ListProjectsResult};
use crate::secrets::{CreateSecretParams, CreateSecretRequest};
use secretpass_core::enums::{ChallengeKind, PasskeyType};
use secretpass_core::{SpassPasskey, SpassProject, SpassSession, SpassUser};
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

    async fn get_user_email(&self, email: String) -> anyhow::Result<Option<SpassUser>>;

    async fn create_session_by_user_id(
        &self,
        passkey_type: PasskeyType,
        user_id: Uuid,
    ) -> anyhow::Result<SessionPackage>;

    async fn retrieve_passkey_by_cred_id(
        &self,
        passkey_type: PasskeyType,
        cred_id: String,
        email: String,
    ) -> anyhow::Result<Option<SpassPasskey>>;

    async fn retrieve_user_and_known_passkeys(
        &self,
        email: String,
        passkey_type: PasskeyType,
    ) -> anyhow::Result<Option<(SpassUser, Vec<SpassPasskey>)>>;

    async fn list_projects(&self, user: &SpassUser) -> anyhow::Result<ListProjectsResult>;

    async fn logout_session(&self, session: &SpassSession) -> anyhow::Result<()>;

    async fn save_passkey(
        &self,
        user: &SpassUser,
        passkey_type: PasskeyType,
        passkey_name: String,
        cred_id: String,
        public_key: String,
    ) -> anyhow::Result<SpassPasskey>;

    async fn create_project(
        &self,
        user: &SpassUser,
        passkeys: &[SpassPasskey],
        request: CreateProjectRequest,
    ) -> anyhow::Result<SpassProject>;

    async fn get_project_by_id(
        &self,
        user: &SpassUser,
        project_id: Uuid,
    ) -> anyhow::Result<Option<GetProjectResult>>;

    async fn get_environment_by_name(
        &self,
        user: &SpassUser,
        request: GetEnvironmentRequest,
    ) -> anyhow::Result<Option<GetEnvironmentResult>>;

    async fn create_secret(
        &self,
        user: &SpassUser,
        params: CreateSecretParams,
        request: CreateSecretRequest,
    ) -> anyhow::Result<SecretWithEncryptedValues>;
}
