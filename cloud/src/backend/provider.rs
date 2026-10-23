use crate::backend::auth::challenge::{
    insert_or_replace_challenge, pop_pending_challenge, retrieve_pending_challenge_for_attempt,
};
use crate::backend::auth::passkey::retrieve_user_id_and_public_key;
use crate::backend::auth::register::create_user;
use crate::backend::auth::session::{
    create_session_by_email, create_session_by_user_id, get_session,
};
use crate::backend::auth::user::retrieve_user_and_known_passkeys;
use secretpass_api::auth::BackendCreateUserRequest;
use secretpass_api::{BackendProvider, PendingChallenge, SessionPackage};
use secretpass_core::enums::{ChallengeKind, PasskeyType};
use secretpass_core::{SecretpassPasskey, SecretpassUser};
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

    async fn create_session_by_user_id(
        &self,
        passkey_type: PasskeyType,
        user_id: Uuid,
    ) -> anyhow::Result<SessionPackage> {
        create_session_by_user_id(&self.pool, passkey_type, user_id).await
    }

    async fn retrieve_user_id_and_public_key(
        &self,
        passkey_type: PasskeyType,
        cred_id: String,
    ) -> anyhow::Result<Option<(Uuid, String)>> {
        retrieve_user_id_and_public_key(&self.pool, passkey_type, cred_id).await
    }

    async fn retrieve_user_and_known_passkeys(
        &self,
        email: String,
        passkey_type: PasskeyType,
    ) -> anyhow::Result<Option<(SecretpassUser, Vec<SecretpassPasskey>)>> {
        retrieve_user_and_known_passkeys(&self.pool, email, passkey_type).await
    }
}
