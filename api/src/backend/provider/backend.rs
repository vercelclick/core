use crate::backend::environments::{
    GetEnvironmentRequest, GetEnvironmentResult, SecretWithEncryptedValues,
};
use crate::backend::projects::{CreateProjectRequest, GetProjectResult, ListProjectsResult};
use crate::backend::secrets::{
    CreateAccessKeyRequest, CreateFederatedAccessKeyRequest, CreateFederatedAccessKeyResult,
    CreateSecretRequest, ProjectAccessKeyParams, ProjectEnvPathParams, ProjectPathParams,
    ProjectSecretPathParams, UpdateSecretRequest, UpdateSecretValueRequest,
};
use click_core::{AccessKey, AuthSession, InternalResult, Project, TargetedPublicKey};
use std::collections::HashMap;
use uuid::Uuid;

#[async_trait::async_trait]
pub trait BackendProvider: Send + Sync + 'static {
    async fn generate_webauthn_authorization_challenge(
        &self,
        session: &AuthSession,
    ) -> InternalResult<String>;

    async fn list_projects(&self, session: &AuthSession) -> InternalResult<ListProjectsResult>;

    async fn create_project(
        &self,
        session: &AuthSession,
        request: CreateProjectRequest,
    ) -> InternalResult<Project>;

    async fn get_project_by_id(
        &self,
        session: &AuthSession,
        project_id: Uuid,
    ) -> InternalResult<Option<GetProjectResult>>;

    async fn get_environment_by_name(
        &self,
        session: &AuthSession,
        request: GetEnvironmentRequest,
    ) -> InternalResult<Option<GetEnvironmentResult>>;

    async fn create_secret(
        &self,
        session: &AuthSession,
        params: ProjectEnvPathParams,
        request: CreateSecretRequest,
    ) -> InternalResult<SecretWithEncryptedValues>;

    async fn get_access_key_secrets(
        &self,
        params: ProjectAccessKeyParams,
    ) -> InternalResult<HashMap<String, String>>;

    async fn create_access_key(
        &self,
        session: &AuthSession,
        params: ProjectPathParams,
        request: CreateAccessKeyRequest,
    ) -> InternalResult<AccessKey>;

    async fn update_secret(
        &self,
        session: &AuthSession,
        params: ProjectSecretPathParams,
        request: UpdateSecretRequest,
    ) -> InternalResult<SecretWithEncryptedValues>;

    async fn update_secret_value(
        &self,
        session: &AuthSession,
        params: ProjectSecretPathParams,
        request: UpdateSecretValueRequest,
    ) -> InternalResult<SecretWithEncryptedValues>;

    async fn get_secret_targets(
        &self,
        session: &AuthSession,
        params: ProjectSecretPathParams,
    ) -> InternalResult<Vec<TargetedPublicKey>>;
    async fn create_federated_access_key(
        &self,
        session: &AuthSession,
        params: ProjectPathParams,
        request: CreateFederatedAccessKeyRequest,
    ) -> InternalResult<CreateFederatedAccessKeyResult>;
}
