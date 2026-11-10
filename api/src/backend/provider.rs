use crate::backend::auth::BackendCreateUserRequest;
use crate::backend::challenge::PendingChallenge;
use crate::backend::environments::{
    GetEnvironmentRequest, GetEnvironmentResult, SecretWithEncryptedValues,
};
use crate::backend::projects::{CreateProjectRequest, GetProjectResult, ListProjectsResult};
use crate::backend::secrets::{
    CreateAccessKeyRequest, CreateFederatedAccessKeyRequest, CreateFederatedAccessKeyResult,
    CreateSecretRequest, ProjectAccessKeyParams, ProjectEnvPathParams, ProjectPathParams,
    ProjectSecretPathParams, UpdateSecretRequest, UpdateSecretValueRequest,
};
use secretpass_core::enums::ChallengeKind;
use secretpass_core::passkeys::public_key::PublicKeyGenerateResult;
use secretpass_core::{
    AccessKey, InternalResult, Passkey, Project, Session, TargetedPublicKey, User,
};
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
    ) -> InternalResult<(Session, User, Vec<Passkey>)>;

    async fn get_session(&self, session_id: Uuid, user_id: Uuid)
    -> InternalResult<Option<Session>>;

    async fn create_session_by_email(
        &self,
        email: String,
    ) -> InternalResult<(Session, User, Vec<Passkey>)>;

    async fn get_user_email(&self, email: String) -> InternalResult<Option<User>>;

    async fn create_session_by_user_id(
        &self,
        user_id: Uuid,
    ) -> InternalResult<(Session, User, Vec<Passkey>)>;

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

    async fn get_access_key_secrets(
        &self,
        params: ProjectAccessKeyParams,
    ) -> InternalResult<HashMap<String, String>>;

    async fn create_access_key(
        &self,
        user: &User,
        params: ProjectPathParams,
        request: CreateAccessKeyRequest,
    ) -> InternalResult<AccessKey>;

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

    async fn get_secret_targets(
        &self,
        user: &User,
        params: &ProjectSecretPathParams,
    ) -> InternalResult<Vec<TargetedPublicKey>>;
    async fn create_federated_access_key(
        &self,
        user: &User,
        params: &ProjectPathParams,
        request: &CreateFederatedAccessKeyRequest,
    ) -> InternalResult<CreateFederatedAccessKeyResult>;
}
