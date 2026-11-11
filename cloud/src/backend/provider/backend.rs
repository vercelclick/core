use crate::backend::auth::challenge::{get_pending_challenge, insert_or_replace_challenge};
use crate::backend::projects::access_keys::{create_access_key, create_federated_access_key};
use crate::backend::projects::environments::get_environment_handler;
use crate::backend::projects::project::{create_project, get_project_by_id, list_projects};
use crate::backend::projects::secrets::create::create_secret;
use crate::backend::projects::secrets::read::get_access_key_secrets;
use crate::backend::projects::secrets::targets::get_secret_targets;
use crate::backend::projects::secrets::update::{update_secret, update_secret_value};
use secretpass_api::backend::environments::{
    GetEnvironmentRequest, GetEnvironmentResult, SecretWithEncryptedValues,
};
use secretpass_api::backend::projects::{
    CreateProjectRequest, GetProjectResult, ListProjectsResult,
};
use secretpass_api::backend::secrets::{
    CreateAccessKeyRequest, CreateFederatedAccessKeyRequest, CreateFederatedAccessKeyResult,
    CreateSecretRequest, ProjectAccessKeyParams, ProjectEnvPathParams, ProjectPathParams,
    ProjectSecretPathParams, UpdateSecretRequest, UpdateSecretValueRequest,
};
use secretpass_api::backend::{BackendProvider, PendingChallenge};
use secretpass_core::enums::ChallengeKind;
use secretpass_core::{AccessKey, InternalResult, Passkey, Project, TargetedPublicKey, User};
use std::collections::HashMap;
use uuid::Uuid;

pub struct CloudBackendProvider();

#[async_trait::async_trait]
impl BackendProvider for CloudBackendProvider {
    async fn record_pending_challenge(&self, challenge: &PendingChallenge) -> InternalResult<()> {
        insert_or_replace_challenge(challenge).await
    }

    async fn get_pending_challenge(
        &self,
        kind: ChallengeKind,
        owner: &str,
    ) -> InternalResult<Option<PendingChallenge>> {
        get_pending_challenge(kind, owner).await
    }

    async fn list_projects(&self, user: &User) -> InternalResult<ListProjectsResult> {
        list_projects(user).await
    }

    async fn create_project(
        &self,
        user: &User,
        passkeys: &[Passkey],
        request: CreateProjectRequest,
    ) -> InternalResult<Project> {
        create_project(user, passkeys, request).await
    }

    async fn get_project_by_id(
        &self,
        user: &User,
        project_id: Uuid,
    ) -> InternalResult<Option<GetProjectResult>> {
        get_project_by_id(user, project_id).await
    }

    async fn get_environment_by_name(
        &self,
        user: &User,
        request: GetEnvironmentRequest,
    ) -> InternalResult<Option<GetEnvironmentResult>> {
        get_environment_handler(user, &request).await
    }

    async fn create_secret(
        &self,
        user: &User,
        params: ProjectEnvPathParams,
        request: CreateSecretRequest,
    ) -> InternalResult<SecretWithEncryptedValues> {
        create_secret(user, params, request).await
    }

    async fn get_access_key_secrets(
        &self,
        params: ProjectAccessKeyParams,
    ) -> InternalResult<HashMap<String, String>> {
        get_access_key_secrets(params).await
    }

    async fn create_access_key(
        &self,
        user: &User,
        params: ProjectPathParams,
        request: CreateAccessKeyRequest,
    ) -> InternalResult<AccessKey> {
        create_access_key(user, params.project_id, request).await
    }

    async fn update_secret(
        &self,
        user: &User,
        params: ProjectSecretPathParams,
        request: UpdateSecretRequest,
    ) -> InternalResult<SecretWithEncryptedValues> {
        update_secret(user, params, request).await
    }

    async fn update_secret_value(
        &self,
        user: &User,
        params: ProjectSecretPathParams,
        request: UpdateSecretValueRequest,
    ) -> InternalResult<SecretWithEncryptedValues> {
        update_secret_value(user, params, request).await
    }

    async fn get_secret_targets(
        &self,
        user: &User,
        params: &ProjectSecretPathParams,
    ) -> InternalResult<Vec<TargetedPublicKey>> {
        get_secret_targets(user, params).await
    }

    async fn create_federated_access_key(
        &self,
        user: &User,
        params: &ProjectPathParams,
        request: &CreateFederatedAccessKeyRequest,
    ) -> InternalResult<CreateFederatedAccessKeyResult> {
        create_federated_access_key(user, params, request).await
    }
}
