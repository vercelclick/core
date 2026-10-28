use crate::backend::auth::challenge::{
    insert_or_replace_challenge, pop_pending_challenge, retrieve_pending_challenge_for_attempt,
};
use crate::backend::auth::passkey::{create_passkey, retrieve_passkey_by_cred_id};
use crate::backend::auth::register::create_user;
use crate::backend::auth::session::{
    create_session_by_email, create_session_by_user_id, expire_session, get_session,
};
use crate::backend::auth::user::{retrieve_user_and_known_passkeys, retrieve_user_by_email};
use crate::backend::projects::environments::get_environment_by_name;
use crate::backend::projects::project::{create_project, get_project_by_id, list_projects};
use secretpass_api::auth::BackendCreateUserRequest;
use secretpass_api::environments::{
    GetEnvironmentRequest, GetEnvironmentResult, SecretWithEncryptedValues,
};
use secretpass_api::projects::{CreateProjectRequest, GetProjectResult, ListProjectsResult};
use secretpass_api::secrets::{CreateSecretParams, CreateSecretRequest};
use secretpass_api::{BackendProvider, PendingChallenge, SessionPackage};
use secretpass_core::enums::{ChallengeKind, PasskeyType};
use secretpass_core::{SpassPasskey, SpassProject, SpassSession, SpassUser};
use sqlx::PgPool;
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

    async fn get_session(
        &self,
        passkey_type: PasskeyType,
        id: Uuid,
    ) -> anyhow::Result<Option<SessionPackage>> {
        get_session(&self.pool, passkey_type, id).await
    }

    async fn create_session_by_email(
        &self,
        passkey_type: PasskeyType,
        email: String,
    ) -> anyhow::Result<SessionPackage> {
        create_session_by_email(&self.pool, passkey_type, email).await
    }

    async fn get_user_email(&self, email: String) -> anyhow::Result<Option<SpassUser>> {
        retrieve_user_by_email(&self.pool, email).await
    }

    async fn create_session_by_user_id(
        &self,
        passkey_type: PasskeyType,
        user_id: Uuid,
    ) -> anyhow::Result<SessionPackage> {
        create_session_by_user_id(&self.pool, passkey_type, user_id).await
    }

    async fn retrieve_passkey_by_cred_id(
        &self,
        passkey_type: PasskeyType,
        cred_id: String,
        email: String,
    ) -> anyhow::Result<Option<SpassPasskey>> {
        retrieve_passkey_by_cred_id(&self.pool, passkey_type, cred_id, email).await
    }

    async fn retrieve_user_and_known_passkeys(
        &self,
        email: String,
        passkey_type: PasskeyType,
    ) -> anyhow::Result<Option<(SpassUser, Vec<SpassPasskey>)>> {
        retrieve_user_and_known_passkeys(&self.pool, email, passkey_type).await
    }

    async fn list_projects(&self, user: &SpassUser) -> anyhow::Result<ListProjectsResult> {
        list_projects(&self.pool, user).await
    }

    async fn logout_session(&self, session: &SpassSession) -> anyhow::Result<()> {
        expire_session(&self.pool, session).await
    }

    async fn save_passkey(
        &self,
        user: &SpassUser,
        passkey_type: PasskeyType,
        passkey_name: String,
        cred_id: String,
        public_key: String,
    ) -> anyhow::Result<SpassPasskey> {
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
        user: &SpassUser,
        passkeys: &[SpassPasskey],
        request: CreateProjectRequest,
    ) -> anyhow::Result<SpassProject> {
        create_project(&self.pool, user, passkeys, request).await
    }

    async fn get_project_by_id(
        &self,
        user: &SpassUser,
        project_id: Uuid,
    ) -> anyhow::Result<Option<GetProjectResult>> {
        get_project_by_id(&self.pool, user, project_id).await
    }

    async fn get_environment_by_name(
        &self,
        user: &SpassUser,
        request: GetEnvironmentRequest,
    ) -> anyhow::Result<Option<GetEnvironmentResult>> {
        get_environment_by_name(&self.pool, user, &request).await
    }

    async fn create_secret(
        &self,
        user: &SpassUser,
        params: CreateSecretParams,
        request: CreateSecretRequest,
    ) -> anyhow::Result<SecretWithEncryptedValues> {
        todo!()
    }
}
