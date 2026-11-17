use crate::backend::environments::{create_environment, get_environment_by_name};
use crate::backend::projects::access_keys::create_access_key;
use crate::backend::projects::project::{create_project, get_project_by_id, list_projects};
use crate::backend::projects::secrets::create::create_secret;
use crate::backend::projects::secrets::update::{update_secret, update_secret_value};
use click_api::backend::environments::{
    CreateEnvironmentRequest, GetEnvironmentRequest, GetEnvironmentResult,
    SecretWithEncryptedValues,
};

use crate::backend::challenge::save_challenge;
use crate::backend::projects::secrets::target::get_secret_targets;
use chrono::{Duration, Utc};
use click_api::backend::BackendProvider;
use click_api::backend::projects::{CreateProjectRequest, GetProjectResult, ListProjectsResult};
use click_api::backend::secrets::{
    CreateAccessKeyRequest, CreateFederatedAccessKeyRequest, CreateFederatedAccessKeyResult,
    CreateSecretRequest, ProjectAccessKeyParams, ProjectEnvPathParams, ProjectPathParams,
    ProjectSecretPathParams, UpdateSecretRequest, UpdateSecretValueRequest,
};
use click_core::enums::WebauthnChallengeKind;
use click_core::{
    AccessKey, AuthSession, InternalError, InternalResult, Project, StatusCode, TargetedPublicKey,
    WebauthnChallenge, caller,
};
use std::collections::HashMap;
use uuid::Uuid;

#[derive(Default)]
pub struct LocalBackendProvider {}

#[async_trait::async_trait]
impl BackendProvider for LocalBackendProvider {
    async fn generate_webauthn_authorization_challenge(
        &self,
        session: &AuthSession,
    ) -> InternalResult<String> {
        let (challenge, hash) = WebauthnChallenge::generate();

        save_challenge(&WebauthnChallenge {
            kind: WebauthnChallengeKind::PasskeyAuthorize,
            owner: session.user.email.clone(),
            value_hash: hash,
            expires_on: Utc::now() + Duration::minutes(5),
        })
        .await;

        Ok(challenge)
    }

    async fn list_projects(&self, session: &AuthSession) -> InternalResult<ListProjectsResult> {
        list_projects(&session.user).await
    }

    async fn create_project(
        &self,
        session: &AuthSession,
        request: CreateProjectRequest,
    ) -> InternalResult<Project> {
        create_project(session, request).await
    }

    async fn get_project_by_id(
        &self,
        session: &AuthSession,
        project_id: Uuid,
    ) -> InternalResult<Option<GetProjectResult>> {
        get_project_by_id(&session.user, project_id).await
    }

    async fn create_environment(
        &self,
        session: &AuthSession,
        project_id: Uuid,
        request: CreateEnvironmentRequest,
    ) -> InternalResult<GetEnvironmentResult> {
        create_environment(session, project_id, request).await
    }

    async fn get_environment_by_name(
        &self,
        session: &AuthSession,
        request: GetEnvironmentRequest,
    ) -> InternalResult<Option<GetEnvironmentResult>> {
        get_environment_by_name(&session.user, &request).await
    }

    async fn create_secret(
        &self,
        session: &AuthSession,
        params: ProjectEnvPathParams,
        request: CreateSecretRequest,
    ) -> InternalResult<SecretWithEncryptedValues> {
        create_secret(session, params, request).await
    }

    async fn get_access_key_secrets(
        &self,
        _params: ProjectAccessKeyParams,
    ) -> InternalResult<HashMap<String, String>> {
        Err(InternalError::new(
            caller!(),
            StatusCode::NOT_IMPLEMENTED,
            "Secrets API not supported on local server. Use `click local run/export`",
        ))
    }

    async fn create_access_key(
        &self,
        session: &AuthSession,
        params: ProjectPathParams,
        request: CreateAccessKeyRequest,
    ) -> InternalResult<AccessKey> {
        create_access_key(session, params.project_id, request).await
    }

    async fn update_secret(
        &self,
        session: &AuthSession,
        params: ProjectSecretPathParams,
        request: UpdateSecretRequest,
    ) -> InternalResult<SecretWithEncryptedValues> {
        update_secret(session, params, request).await
    }

    async fn update_secret_value(
        &self,
        session: &AuthSession,
        params: ProjectSecretPathParams,
        request: UpdateSecretValueRequest,
    ) -> InternalResult<SecretWithEncryptedValues> {
        update_secret_value(session, params, request).await
    }

    async fn get_secret_targets(
        &self,
        session: &AuthSession,
        params: ProjectSecretPathParams,
    ) -> InternalResult<Vec<TargetedPublicKey>> {
        get_secret_targets(session, params).await
    }

    async fn create_federated_access_key(
        &self,
        _session: &AuthSession,
        _params: ProjectPathParams,
        _request: CreateFederatedAccessKeyRequest,
    ) -> InternalResult<CreateFederatedAccessKeyResult> {
        todo!()
    }
}
