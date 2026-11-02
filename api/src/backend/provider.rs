use crate::auth::BackendCreateUserRequest;
use crate::backend::auth::SessionPackage;
use crate::backend::challenge::PendingChallenge;
use crate::environments::{GetEnvironmentRequest, GetEnvironmentResult, SecretWithEncryptedValues};
use crate::projects::{CreateProjectRequest, GetProjectResult, ListProjectsResult};
use crate::secrets::{
    CreateMachinePublicKeyRequest, CreateSecretRequest, GetMachineSecretParams,
    ProjectEnvPathParams, ProjectPathParams,
};
use secretpass_core::enums::{ChallengeKind, PasskeyType};
use secretpass_core::passkeys::public_key::PublicKeyGenerateResult;
use secretpass_core::{MachinePublicKey, Passkey, Project, Session, User};
use std::collections::HashMap;
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

    async fn get_session(&self, id: Uuid) -> anyhow::Result<Option<SessionPackage>>;

    async fn create_session_by_email(&self, email: String) -> anyhow::Result<SessionPackage>;

    async fn get_user_email(&self, email: String) -> anyhow::Result<Option<User>>;

    async fn create_session_by_user_id(&self, user_id: Uuid) -> anyhow::Result<SessionPackage>;

    async fn retrieve_passkey_by_cred_id(
        &self,
        cred_id: String,
        email: String,
    ) -> anyhow::Result<Option<Passkey>>;

    async fn retrieve_user_and_known_passkeys(
        &self,
        email: String,
    ) -> anyhow::Result<Option<(User, Vec<Passkey>)>>;

    async fn list_projects(&self, user: &User) -> anyhow::Result<ListProjectsResult>;

    async fn logout_session(&self, session: &Session) -> anyhow::Result<()>;

    async fn save_passkey(
        &self,
        user: &User,
        passkey_type: PasskeyType,
        passkey_name: String,
        cred_id: String,
        public_key: String,
        public_key_result: PublicKeyGenerateResult,
    ) -> anyhow::Result<Passkey>;

    async fn create_project(
        &self,
        user: &User,
        passkeys: &[Passkey],
        request: CreateProjectRequest,
    ) -> anyhow::Result<Project>;

    async fn get_project_by_id(
        &self,
        user: &User,
        project_id: Uuid,
    ) -> anyhow::Result<Option<GetProjectResult>>;

    async fn get_environment_by_name(
        &self,
        user: &User,
        request: GetEnvironmentRequest,
    ) -> anyhow::Result<Option<GetEnvironmentResult>>;

    async fn create_secret(
        &self,
        user: &User,
        params: ProjectEnvPathParams,
        request: CreateSecretRequest,
    ) -> anyhow::Result<SecretWithEncryptedValues>;

    async fn get_machine_secrets(
        &self,
        params: GetMachineSecretParams,
    ) -> anyhow::Result<HashMap<String, String>>;

    async fn create_machine_public_key(
        &self,
        user: &User,
        params: ProjectPathParams,
        request: CreateMachinePublicKeyRequest,
    ) -> anyhow::Result<MachinePublicKey>;
}
