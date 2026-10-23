use crate::backend::auth::challenge::{
    insert_or_replace_challenge, pop_pending_challenge, retrieve_pending_challenge_for_attempt,
};
use crate::backend::auth::passkey::retrieve_user_id_and_public_key;
use crate::backend::auth::register::create_user;
use crate::backend::auth::session::{
    create_session_by_email, create_session_by_user_and_cred_id, get_session,
};
use secretpass_api::auth::BackendCreateUserRequest;
use secretpass_api::{BackendProvider, PendingChallenge, SessionPackage};
use secretpass_core::enums::{ChallengeKind, PasskeyType};
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
    async fn record_pending_challenge(&self, challenge: PendingChallenge) -> anyhow::Result<()> {
        insert_or_replace_challenge(&self.pool, challenge).await
    }

    async fn retrieve_pending_challenge_for_attempt(
        &self,
        kind: ChallengeKind,
        owner: String,
    ) -> anyhow::Result<PendingChallenge> {
        retrieve_pending_challenge_for_attempt(&self.pool, kind, owner).await
    }

    async fn pop_pending_challenge(
        &self,
        kind: ChallengeKind,
        owner: String,
    ) -> anyhow::Result<PendingChallenge> {
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
        id: String,
    ) -> anyhow::Result<SessionPackage> {
        get_session(&self.pool, passkey_type, id).await
    }

    async fn create_session_by_email(
        &self,
        passkey_type: PasskeyType,
        email: String,
    ) -> anyhow::Result<SessionPackage> {
        create_session_by_email(&self.pool, passkey_type, email).await
    }

    async fn create_session_by_user_and_cred_id(
        &self,
        passkey_type: PasskeyType,
        user_id: String,
        cred_id: String,
    ) -> anyhow::Result<SessionPackage> {
        create_session_by_user_and_cred_id(&self.pool, passkey_type, user_id, cred_id).await
    }

    async fn retrieve_user_id_and_public_key(
        &self,
        passkey_type: PasskeyType,
        cred_id: String,
    ) -> anyhow::Result<(String, String)> {
        retrieve_user_id_and_public_key(&self.pool, passkey_type, cred_id).await
    }
}
