use crate::backend::projects::access_keys::{create_access_key, create_federated_access_key};
use crate::backend::projects::environments::get_environment_handler;
use crate::backend::projects::project::{create_project, get_project_by_id, list_projects};
use crate::backend::projects::secrets::create::create_secret;
use crate::backend::projects::secrets::read::get_access_key_secrets;
use crate::backend::projects::secrets::targets::get_secret_targets;
use crate::backend::projects::secrets::update::{update_secret, update_secret_value};
use crate::db;
use crate::db::workflows::UpsertWebauthnChallengeWorkflow;
use click_api::backend::BackendProvider;
use click_api::backend::environments::{
    GetEnvironmentRequest, GetEnvironmentResult, SecretWithEncryptedValues,
};
use click_api::backend::projects::{CreateProjectRequest, GetProjectResult, ListProjectsResult};
use click_api::backend::secrets::{
    CreateAccessKeyRequest, CreateFederatedAccessKeyRequest, CreateFederatedAccessKeyResult,
    CreateSecretRequest, ProjectAccessKeyParams, ProjectEnvPathParams, ProjectPathParams,
    ProjectSecretPathParams, UpdateSecretRequest, UpdateSecretValueRequest,
};
use click_core::enums::WebauthnChallengeKind;
use click_core::{
    AccessKey, AuthSession, InternalResult, Project, TargetedPublicKey, WebauthnChallenge,
};
use std::collections::HashMap;
use uuid::Uuid;

pub struct CloudBackendProvider();

#[async_trait::async_trait]
impl BackendProvider for CloudBackendProvider {
    async fn generate_webauthn_authorization_challenge(
        &self,
        session: &AuthSession,
    ) -> InternalResult<String> {
        let (challenge, hash) = WebauthnChallenge::generate();

        db::with_transaction(UpsertWebauthnChallengeWorkflow {
            owner: session.user.email.clone(),
            kind: WebauthnChallengeKind::PasskeyAuthorize,
            hash,
        })
        .await?;

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

    async fn get_environment_by_name(
        &self,
        session: &AuthSession,
        request: GetEnvironmentRequest,
    ) -> InternalResult<Option<GetEnvironmentResult>> {
        get_environment_handler(&session.user, &request).await
    }

    async fn create_secret(
        &self,
        session: &AuthSession,
        params: ProjectEnvPathParams,
        request: CreateSecretRequest,
    ) -> InternalResult<SecretWithEncryptedValues> {
        create_secret(&session.user, params, request).await
    }

    async fn get_access_key_secrets(
        &self,
        params: ProjectAccessKeyParams,
    ) -> InternalResult<HashMap<String, String>> {
        get_access_key_secrets(params).await
    }

    async fn create_access_key(
        &self,
        session: &AuthSession,
        params: ProjectPathParams,
        request: CreateAccessKeyRequest,
    ) -> InternalResult<AccessKey> {
        create_access_key(&session.user, params.project_id, request).await
    }

    async fn update_secret(
        &self,
        session: &AuthSession,
        params: ProjectSecretPathParams,
        request: UpdateSecretRequest,
    ) -> InternalResult<SecretWithEncryptedValues> {
        update_secret(&session.user, params, request).await
    }

    async fn update_secret_value(
        &self,
        session: &AuthSession,
        params: ProjectSecretPathParams,
        request: UpdateSecretValueRequest,
    ) -> InternalResult<SecretWithEncryptedValues> {
        update_secret_value(&session.user, params, request).await
    }

    async fn get_secret_targets(
        &self,
        session: &AuthSession,
        params: ProjectSecretPathParams,
    ) -> InternalResult<Vec<TargetedPublicKey>> {
        get_secret_targets(&session.user, params).await
    }

    async fn create_federated_access_key(
        &self,
        session: &AuthSession,
        params: ProjectPathParams,
        request: CreateFederatedAccessKeyRequest,
    ) -> InternalResult<CreateFederatedAccessKeyResult> {
        create_federated_access_key(&session.user, params, request).await
    }
}
