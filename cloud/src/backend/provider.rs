use crate::backend::auth::challenge::{
    insert_or_replace_challenge, pop_pending_challenge, retrieve_pending_challenge_for_attempt,
};
use crate::backend::auth::passkey::{create_passkey, retrieve_passkey_by_cred_id};
use crate::backend::auth::register::create_user;
use crate::backend::auth::session::{
    create_session_by_email, create_session_by_user_id, expire_session, get_session,
};
use crate::backend::auth::user::{retrieve_user_and_known_passkeys, retrieve_user_by_email};
use crate::backend::projects::environments::get_environment_handler;
use crate::backend::projects::machine::create_machine_public_key;
use crate::backend::projects::project::{create_project, get_project_by_id, list_projects};
use crate::backend::projects::secrets::create::create_secret;
use crate::backend::projects::secrets::read::get_machine_secrets;
use secretpass_api::auth::BackendCreateUserRequest;
use secretpass_api::environments::{
    GetEnvironmentRequest, GetEnvironmentResult, SecretWithEncryptedValues,
};
use secretpass_api::projects::{CreateProjectRequest, GetProjectResult, ListProjectsResult};
use secretpass_api::secrets::{
    CreateMachinePublicKeyRequest, CreateSecretRequest, GetMachineSecretParams,
    ProjectEnvPathParams, ProjectPathParams,
};
use secretpass_api::{BackendProvider, PendingChallenge, SessionPackage};
use secretpass_core::enums::{ChallengeKind, PasskeyType};
use secretpass_core::{MachinePublicKey, Passkey, Project, Session, User};
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
    async fn record_pending_challenge(&self, challenge: &PendingChallenge) -> anyhow::Result<()> {
        insert_or_replace_challenge(&self.pool, challenge).await
    }

    async fn retrieve_pending_challenge_for_attempt(
        &self,
        kind: ChallengeKind,
        owner: String,
    ) -> anyhow::Result<Option<PendingChallenge>> {
        retrieve_pending_challenge_for_attempt(&self.pool, kind, owner).await
    }

    async fn pop_pending_challenge(
        &self,
        kind: ChallengeKind,
        owner: String,
    ) -> anyhow::Result<Option<PendingChallenge>> {
        pop_pending_challenge(&self.pool, kind, owner).await
    }

    async fn create_user(
        &self,
        request: BackendCreateUserRequest,
    ) -> anyhow::Result<SessionPackage> {
        create_user(&self.pool, request).await
    }

    async fn record_session(&self, _session: SessionPackage) -> anyhow::Result<()> {
        Err(anyhow::anyhow!(
            "Record session details not supported on cloud; please report an issue to support@secretpass.cloud"
        ))
    }

    async fn get_session(&self, id: Uuid) -> anyhow::Result<Option<SessionPackage>> {
        get_session(&self.pool, id).await
    }

    async fn create_session_by_email(&self, email: String) -> anyhow::Result<SessionPackage> {
        create_session_by_email(&self.pool, email).await
    }

    async fn get_user_email(&self, email: String) -> anyhow::Result<Option<User>> {
        retrieve_user_by_email(&self.pool, email).await
    }

    async fn create_session_by_user_id(&self, user_id: Uuid) -> anyhow::Result<SessionPackage> {
        create_session_by_user_id(&self.pool, user_id).await
    }

    async fn retrieve_passkey_by_cred_id(
        &self,
        cred_id: String,
        email: String,
    ) -> anyhow::Result<Option<Passkey>> {
        retrieve_passkey_by_cred_id(&self.pool, cred_id, email).await
    }

    async fn retrieve_user_and_known_passkeys(
        &self,
        email: String,
    ) -> anyhow::Result<Option<(User, Vec<Passkey>)>> {
        retrieve_user_and_known_passkeys(&self.pool, email).await
    }

    async fn list_projects(&self, user: &User) -> anyhow::Result<ListProjectsResult> {
        list_projects(&self.pool, user).await
    }

    async fn logout_session(&self, session: &Session) -> anyhow::Result<()> {
        expire_session(&self.pool, session).await
    }

    async fn save_passkey(
        &self,
        user: &User,
        passkey_type: PasskeyType,
        passkey_name: String,
        cred_id: String,
        public_key: String,
    ) -> anyhow::Result<Passkey> {
        create_passkey(
            &self.pool,
            user,
            passkey_type,
            passkey_name,
            cred_id,
            public_key,
        )
        .await
    }

    async fn create_project(
        &self,
        user: &User,
        passkeys: &[Passkey],
        request: CreateProjectRequest,
    ) -> anyhow::Result<Project> {
        create_project(&self.pool, user, passkeys, request).await
    }

    async fn get_project_by_id(
        &self,
        user: &User,
        project_id: Uuid,
    ) -> anyhow::Result<Option<GetProjectResult>> {
        get_project_by_id(&self.pool, user, project_id).await
    }

    async fn get_environment_by_name(
        &self,
        user: &User,
        request: GetEnvironmentRequest,
    ) -> anyhow::Result<Option<GetEnvironmentResult>> {
        get_environment_handler(&self.pool, user, &request).await
    }

    async fn create_secret(
        &self,
        user: &User,
        params: ProjectEnvPathParams,
        request: CreateSecretRequest,
    ) -> anyhow::Result<SecretWithEncryptedValues> {
        create_secret(&self.pool, user, params, request).await
    }

    async fn get_machine_secrets(
        &self,
        params: GetMachineSecretParams,
    ) -> anyhow::Result<HashMap<String, String>> {
        get_machine_secrets(&self.pool, params).await
    }

    async fn create_machine_public_key(
        &self,
        user: &User,
        params: ProjectPathParams,
        request: CreateMachinePublicKeyRequest,
    ) -> anyhow::Result<MachinePublicKey> {
        create_machine_public_key(&self.pool, user, params.project_id, request).await
    }
}
