use crate::backend::challenge::{get_pending_challenge, save_pending_challenge};
use crate::backend::environments::get_environment_by_name;
use crate::backend::projects::access_keys::create_access_key;
use crate::backend::projects::project::{create_project, get_project_by_id, list_projects};
use crate::backend::projects::secrets::create::create_secret;
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
use secretpass_core::{
    AccessKey, InternalError, InternalResult, Passkey, Project, StatusCode, TargetedPublicKey, User,
};
use std::collections::HashMap;
use uuid::Uuid;

#[derive(Default)]
pub struct LocalBackendProvider {}

#[async_trait::async_trait]
impl BackendProvider for LocalBackendProvider {
    async fn record_pending_challenge(&self, challenge: &PendingChallenge) -> InternalResult<()> {
        save_pending_challenge(challenge).await;
        Ok(())
    }

    async fn get_pending_challenge(
        &self,
        kind: ChallengeKind,
        owner: &str,
    ) -> InternalResult<Option<PendingChallenge>> {
        let challenge = get_pending_challenge(kind, owner).await;
        Ok(challenge)
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
        get_environment_by_name(user, &request).await
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
        _params: ProjectAccessKeyParams,
    ) -> InternalResult<HashMap<String, String>> {
        Err(InternalError::new(
            StatusCode::NOT_IMPLEMENTED,
            "Secrets API not supported on local server. Use `spass local run/export`",
        ))
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
        _user: &User,
        _params: &ProjectSecretPathParams,
    ) -> InternalResult<Vec<TargetedPublicKey>> {
        todo!()
    }

    async fn create_federated_access_key(
        &self,
        _user: &User,
        _params: &ProjectPathParams,
        _request: &CreateFederatedAccessKeyRequest,
    ) -> InternalResult<CreateFederatedAccessKeyResult> {
        todo!()
    }
}
