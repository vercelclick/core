use crate::auth::BackendCreateUserRequest;
use crate::backend::auth::SessionPackage;
use crate::backend::challenge::PendingChallenge;
use crate::environments::{GetEnvironmentRequest, GetEnvironmentResult, SecretWithEncryptedValues};
use crate::projects::{CreateProjectRequest, GetProjectResult, ListProjectsResult};
use crate::secrets::{
    CreateMachinePublicKeyRequest, CreateSecretRequest, GetMachineSecretParams,
    ProjectEnvPathParams, ProjectPathParams, ProjectSecretPathParams, UpdateSecretRequest,
    UpdateSecretValueRequest,
};
use secretpass_core::enums::ChallengeKind;
use secretpass_core::passkeys::public_key::PublicKeyGenerateResult;
use secretpass_core::{InternalResult, MachinePublicKey, Passkey, Project, Session, User};
use std::collections::HashMap;
use uuid::Uuid;

#[async_trait::async_trait]
pub trait BackendProvider: Send + Sync + 'static {
    async fn record_pending_challenge(&self, challenge: &PendingChallenge) -> InternalResult<()>;

    async fn retrieve_pending_challenge_for_attempt(
        &self,
        kind: ChallengeKind,
        owner: String,
    ) -> InternalResult<Option<PendingChallenge>>;

    async fn get_pending_challenge(
        &self,
        kind: ChallengeKind,
        owner: String,
    ) -> InternalResult<Option<PendingChallenge>>;

    async fn create_user(
        &self,
        request: BackendCreateUserRequest,
    ) -> InternalResult<SessionPackage>;

    // Only called for local
    async fn record_session(&self, response: SessionPackage) -> InternalResult<()>;

    async fn get_session(&self, id: Uuid) -> InternalResult<Option<SessionPackage>>;

    async fn create_session_by_email(&self, email: String) -> InternalResult<SessionPackage>;

    async fn get_user_email(&self, email: String) -> InternalResult<Option<User>>;

    async fn create_session_by_user_id(&self, user_id: Uuid) -> InternalResult<SessionPackage>;

    async fn retrieve_passkey_by_cred_id(
        &self,
        cred_id: String,
        email: String,
    ) -> InternalResult<Option<Passkey>>;

    async fn retrieve_user_and_known_passkeys(
        &self,
        email: String,
    ) -> InternalResult<Option<(User, Vec<Passkey>)>>;

    async fn list_projects(&self, user: &User) -> InternalResult<ListProjectsResult>;

    async fn logout_session(&self, session: &Session) -> InternalResult<()>;

    async fn save_passkey(
        &self,
        user: &User,
        passkey_name: String,
        cred_id: String,
        public_key: String,
        public_key_result: PublicKeyGenerateResult,
    ) -> InternalResult<Passkey>;

    async fn create_project(
        &self,
        user: &User,
        passkeys: &[Passkey],
        request: CreateProjectRequest,
    ) -> InternalResult<Project>;

    async fn get_project_by_id(
        &self,
        user: &User,
        project_id: Uuid,
    ) -> InternalResult<Option<GetProjectResult>>;

    async fn get_environment_by_name(
        &self,
        user: &User,
        request: GetEnvironmentRequest,
    ) -> InternalResult<Option<GetEnvironmentResult>>;

    async fn create_secret(
        &self,
        user: &User,
        params: ProjectEnvPathParams,
        request: CreateSecretRequest,
    ) -> InternalResult<SecretWithEncryptedValues>;

    async fn get_machine_secrets(
        &self,
        params: GetMachineSecretParams,
    ) -> InternalResult<HashMap<String, String>>;

    async fn create_machine_public_key(
        &self,
        user: &User,
        params: ProjectPathParams,
        request: CreateMachinePublicKeyRequest,
    ) -> InternalResult<MachinePublicKey>;

    async fn update_secret(
        &self,
        user: &User,
        params: ProjectSecretPathParams,
        request: UpdateSecretRequest,
    ) -> InternalResult<SecretWithEncryptedValues>;

    async fn update_secret_value(
        &self,
        user: &User,
        params: ProjectSecretPathParams,
        request: UpdateSecretValueRequest,
    ) -> InternalResult<SecretWithEncryptedValues>;
}
