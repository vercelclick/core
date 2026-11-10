use crate::backend::auth::challenge::{
    get_pending_challenge, insert_or_replace_challenge, retrieve_pending_challenge_for_attempt,
};
use crate::backend::auth::passkey::{create_passkey, retrieve_passkey_by_cred_id};
use crate::backend::auth::register::create_user;
use crate::backend::auth::session::{
    create_session_by_email, create_session_by_user_id, expire_session, get_session,
};
use crate::backend::auth::user::{retrieve_user_and_known_passkeys, retrieve_user_by_email};
use crate::backend::projects::access_keys::{create_access_key, create_federated_access_key};
use crate::backend::projects::environments::get_environment_handler;
use crate::backend::projects::project::{create_project, get_project_by_id, list_projects};
use crate::backend::projects::secrets::create::create_secret;
use crate::backend::projects::secrets::read::get_access_key_secrets;
use crate::backend::projects::secrets::targets::get_secret_targets;
use crate::backend::projects::secrets::update::{update_secret, update_secret_value};
use secretpass_api::backend::auth::BackendCreateUserRequest;
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
use secretpass_api::backend::{BackendProvider, PendingChallenge, SessionPackage};
use secretpass_core::enums::ChallengeKind;
use secretpass_core::passkeys::public_key::PublicKeyGenerateResult;
use secretpass_core::{
    AccessKey, InternalError, InternalResult, Passkey, Project, Session, StatusCode,
    TargetedPublicKey, User,
};
use sqlx::PgPool;
use std::collections::HashMap;
use std::sync::Arc;
use uuid::Uuid;

pub struct CloudBackendProvider {
    pool: Arc<PgPool>,
}

impl CloudBackendProvider {
    pub fn new(pool: PgPool) -> Self {
        CloudBackendProvider {
            pool: Arc::new(pool),
        }
    }
}

#[async_trait::async_trait]
impl BackendProvider for CloudBackendProvider {
    async fn record_pending_challenge(&self, challenge: &PendingChallenge) -> InternalResult<()> {
        insert_or_replace_challenge(&self.pool, challenge).await
    }

    async fn retrieve_pending_challenge_for_attempt(
        &self,
        kind: ChallengeKind,
        owner: String,
    ) -> InternalResult<Option<PendingChallenge>> {
        retrieve_pending_challenge_for_attempt(&self.pool, kind, owner).await
    }

    async fn get_pending_challenge(
        &self,
        kind: ChallengeKind,
        owner: String,
    ) -> InternalResult<Option<PendingChallenge>> {
        get_pending_challenge(&self.pool, kind, owner).await
    }

    async fn create_user(
        &self,
        request: BackendCreateUserRequest,
    ) -> InternalResult<SessionPackage> {
        create_user(&self.pool, request).await
    }

    async fn record_session(&self, _session: SessionPackage) -> InternalResult<()> {
        Err(InternalError::new(
            StatusCode::NOT_IMPLEMENTED,
            "Record session details not supported on cloud; please report an issue to support@secretpass.cloud",
        ))
    }

    async fn get_session(&self, id: Uuid) -> InternalResult<Option<SessionPackage>> {
        get_session(&self.pool, id).await
    }

    async fn create_session_by_email(&self, email: String) -> InternalResult<SessionPackage> {
        create_session_by_email(&self.pool, email).await
    }

    async fn get_user_email(&self, email: String) -> InternalResult<Option<User>> {
        retrieve_user_by_email(&self.pool, email).await
    }

    async fn create_session_by_user_id(&self, user_id: Uuid) -> InternalResult<SessionPackage> {
        create_session_by_user_id(&self.pool, user_id).await
    }

    async fn retrieve_passkey_by_cred_id(
        &self,
        cred_id: String,
        email: String,
    ) -> InternalResult<Option<Passkey>> {
        retrieve_passkey_by_cred_id(&self.pool, cred_id, email).await
    }

    async fn retrieve_user_and_known_passkeys(
        &self,
        email: String,
    ) -> InternalResult<Option<(User, Vec<Passkey>)>> {
        retrieve_user_and_known_passkeys(&self.pool, email).await
    }

    async fn list_projects(&self, user: &User) -> InternalResult<ListProjectsResult> {
        list_projects(&self.pool, user).await
    }

    async fn logout_session(&self, session: &Session) -> InternalResult<()> {
        expire_session(&self.pool, session).await
    }

    async fn save_passkey(
        &self,
        user: &User,
        passkey_name: String,
        cred_id: String,
        web_public_key: String,
        public_key_result: PublicKeyGenerateResult,
    ) -> InternalResult<Passkey> {
        create_passkey(
            &self.pool,
            user,
            passkey_name,
            cred_id,
            web_public_key,
            public_key_result,
        )
        .await
    }

    async fn create_project(
        &self,
        user: &User,
        passkeys: &[Passkey],
        request: CreateProjectRequest,
    ) -> InternalResult<Project> {
        create_project(&self.pool, user, passkeys, request).await
    }

    async fn get_project_by_id(
        &self,
        user: &User,
        project_id: Uuid,
    ) -> InternalResult<Option<GetProjectResult>> {
        get_project_by_id(&self.pool, user, project_id).await
    }

    async fn get_environment_by_name(
        &self,
        user: &User,
        request: GetEnvironmentRequest,
    ) -> InternalResult<Option<GetEnvironmentResult>> {
        get_environment_handler(&self.pool, user, &request).await
    }

    async fn create_secret(
        &self,
        user: &User,
        params: ProjectEnvPathParams,
        request: CreateSecretRequest,
    ) -> InternalResult<SecretWithEncryptedValues> {
        create_secret(&self.pool, user, params, request).await
    }

    async fn get_access_key_secrets(
        &self,
        params: ProjectAccessKeyParams,
    ) -> InternalResult<HashMap<String, String>> {
        get_access_key_secrets(&self.pool, params).await
    }

    async fn create_access_key(
        &self,
        user: &User,
        params: ProjectPathParams,
        request: CreateAccessKeyRequest,
    ) -> InternalResult<AccessKey> {
        create_access_key(&self.pool, user, params.project_id, request).await
    }

    async fn update_secret(
        &self,
        user: &User,
        params: ProjectSecretPathParams,
        request: UpdateSecretRequest,
    ) -> InternalResult<SecretWithEncryptedValues> {
        update_secret(&self.pool, user, params, request).await
    }

    async fn update_secret_value(
        &self,
        user: &User,
        params: ProjectSecretPathParams,
        request: UpdateSecretValueRequest,
    ) -> InternalResult<SecretWithEncryptedValues> {
        update_secret_value(&self.pool, user, params, request).await
    }

    async fn get_secret_targets(
        &self,
        user: &User,
        params: &ProjectSecretPathParams,
    ) -> InternalResult<Vec<TargetedPublicKey>> {
        get_secret_targets(&self.pool, user, params).await
    }

    async fn create_federated_access_key(
        &self,
        user: &User,
        params: &ProjectPathParams,
        request: &CreateFederatedAccessKeyRequest,
    ) -> InternalResult<CreateFederatedAccessKeyResult> {
        create_federated_access_key(&self.pool, user, params, request).await
    }
}
