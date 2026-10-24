use crate::backend::challenge::{get_pending_challenge, save_pending_challenge};
use crate::config::LocalServiceConfig;
use secretpass_api::auth::BackendCreateUserRequest;
use secretpass_api::projects::ListProjectsResult;
use secretpass_api::{BackendProvider, PendingChallenge, SessionPackage};
use secretpass_core::enums::{ChallengeKind, PasskeyType};
use secretpass_core::{SecretpassPasskey, SecretpassUser};
use uuid::Uuid;

#[derive(Default)]
pub struct LocalBackendProvider {}

fn not_supported(title: &str) -> anyhow::Error {
    anyhow::format_err!(
        "{title} not supported locally; this call should have been proxied, please report an issue to support@secretpass.cloud"
    )
}

#[async_trait::async_trait]
impl BackendProvider for LocalBackendProvider {
    async fn record_pending_challenge(&self, challenge: &PendingChallenge) -> anyhow::Result<()> {
        save_pending_challenge(challenge).await;
        Ok(())
    }

    async fn retrieve_pending_challenge_for_attempt(
        &self,
        _kind: ChallengeKind,
        _owner: String,
    ) -> anyhow::Result<Option<PendingChallenge>> {
        Err(not_supported("Challenge attempts"))
    }

    async fn pop_pending_challenge(
        &self,
        kind: ChallengeKind,
        owner: String,
    ) -> anyhow::Result<Option<PendingChallenge>> {
        let challenge = get_pending_challenge(kind, owner).await;
        Ok(challenge)
    }

    async fn create_user(
        &self,
        _request: BackendCreateUserRequest,
    ) -> anyhow::Result<SessionPackage> {
        Err(not_supported("Create user"))
    }

    async fn record_session(&self, response: SessionPackage) -> anyhow::Result<()> {
        let mut config = LocalServiceConfig::load()?;
        config
            .sessions
            .insert(response.session.id.to_string(), response);

        config.write()
    }

    async fn get_session(
        &self,
        passkey_type: PasskeyType,
        id: Uuid,
    ) -> anyhow::Result<Option<SessionPackage>> {
        if passkey_type != PasskeyType::Local {
            return Err(not_supported("Get session with cloud passkeys"));
        }
        let config = LocalServiceConfig::load()?;

        let response = config.sessions.get(&id.to_string());
        Ok(response.cloned())
    }

    async fn create_session_by_email(
        &self,
        _passkey_type: PasskeyType,
        _email: String,
    ) -> anyhow::Result<SessionPackage> {
        Err(not_supported("Create session by email"))
    }

    async fn get_user_email(
        &self,
        _email: String,
    ) -> anyhow::Result<Option<(i32, SecretpassUser)>> {
        Err(not_supported("Retrieve user by email"))
    }

    async fn create_session_by_user_id(
        &self,
        _passkey_type: PasskeyType,
        _user_id: Uuid,
    ) -> anyhow::Result<SessionPackage> {
        Err(not_supported("Create session by passkey"))
    }

    async fn retrieve_user_id_and_public_key(
        &self,
        _passkey_type: PasskeyType,
        _cred_id: String,
    ) -> anyhow::Result<Option<(Uuid, String)>> {
        Err(not_supported("Retrieve user id and public key"))
    }

    async fn retrieve_user_and_known_passkeys(
        &self,
        _email: String,
        _passkey_type: PasskeyType,
    ) -> anyhow::Result<Option<(SecretpassUser, Vec<SecretpassPasskey>)>> {
        Err(not_supported("Retrieve user with passkeys"))
    }

    async fn list_projects(&self, _user: &SecretpassUser) -> anyhow::Result<ListProjectsResult> {
        todo!()
    }
}
