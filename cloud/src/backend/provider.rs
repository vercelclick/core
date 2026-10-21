use crate::backend::auth::challenge::{get_pending_challenge, insert_or_replace_challenge};
use crate::backend::auth::register::create_user;
use secretpass_api::{BackendProvider, CreateUserParams, PendingChallenge, SessionResponse};
use secretpass_core::enums::ChallengeKind;
use secretpass_core::{SecretpassUser, SecretpassUserSession};
use sqlx::PgPool;
use std::sync::Arc;

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
    async fn pending_challenge_record(
        &self,
        challenge: secretpass_api::PendingChallenge,
    ) -> anyhow::Result<()> {
        insert_or_replace_challenge(&self.pool, challenge).await
    }

    async fn pending_challenge_retrieve(
        &self,
        kind: ChallengeKind,
        challenge: String,
    ) -> anyhow::Result<PendingChallenge> {
        get_pending_challenge(&self.pool, kind, challenge).await
    }

    async fn projects_list(&self) -> anyhow::Result<()> {
        todo!()
    }

    async fn projects_get(&self, _id: &str) -> anyhow::Result<()> {
        todo!()
    }

    async fn workspaces_list(&self) -> anyhow::Result<()> {
        todo!()
    }

    async fn create_user(&self, params: CreateUserParams) -> anyhow::Result<SessionResponse> {
        create_user(&self.pool, params).await
    }

    async fn record_session(
        &self,
        _user: SecretpassUser,
        _session: SecretpassUserSession,
    ) -> anyhow::Result<()> {
        Err(anyhow::anyhow!(
            "Cloud provider shouldn't call record session!"
        ))
    }

    async fn get_session(&self, id: String) -> anyhow::Result<Option<SessionResponse>> {
        todo!()
    }
}
