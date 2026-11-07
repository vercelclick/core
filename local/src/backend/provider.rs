use crate::backend::challenge::{get_pending_challenge, save_pending_challenge};
use crate::backend::environments::get_environment_by_name;
use crate::backend::projects::machine::create_machine_public_key;
use crate::backend::projects::project::{create_project, get_project_by_id, list_projects};
use crate::backend::projects::secrets::create::create_secret;
use crate::backend::projects::secrets::update::{update_secret, update_secret_value};
use crate::config::LocalServiceConfig;
use secretpass_api::auth::BackendCreateUserRequest;
use secretpass_api::environments::{
    GetEnvironmentRequest, GetEnvironmentResult, SecretWithEncryptedValues,
};
use secretpass_api::projects::{CreateProjectRequest, GetProjectResult, ListProjectsResult};
use secretpass_api::secrets::{
    CreateMachinePublicKeyRequest, CreateSecretRequest, GetMachineSecretParams,
    ProjectEnvPathParams, ProjectPathParams, ProjectSecretPathParams, UpdateSecretRequest,
    UpdateSecretValueRequest,
};
use secretpass_api::{BackendProvider, PendingChallenge, SessionPackage};
use secretpass_core::enums::{ChallengeKind, PasskeyType};
use secretpass_core::passkeys::public_key::PublicKeyGenerateResult;
use secretpass_core::{MachinePublicKey, Passkey, Project, Session, User};
use std::collections::HashMap;
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
        config.sessions.insert(response.session.id, response);

        config.write()
    }

    async fn get_session(&self, id: Uuid) -> anyhow::Result<Option<SessionPackage>> {
        let config = LocalServiceConfig::load()?;

        let response = config.sessions.get(&id);
        Ok(response.cloned())
    }

    async fn create_session_by_email(&self, _email: String) -> anyhow::Result<SessionPackage> {
        Err(not_supported("Create session by email"))
    }

    async fn get_user_email(&self, email: String) -> anyhow::Result<Option<User>> {
        let local_conf = LocalServiceConfig::load()?;
        for (_, package) in local_conf.sessions {
            if package.user.email == email {
                return Ok(Some((*package.user).clone()));
            }
        }
        Ok(None)
    }

    async fn create_session_by_user_id(&self, _user_id: Uuid) -> anyhow::Result<SessionPackage> {
        Err(not_supported("Create session by passkey"))
    }

    async fn retrieve_passkey_by_cred_id(
        &self,
        _cred_id: String,
        _email: String,
    ) -> anyhow::Result<Option<Passkey>> {
        Err(not_supported("Retrieve user id and public key"))
    }

    async fn retrieve_user_and_known_passkeys(
        &self,
        _email: String,
    ) -> anyhow::Result<Option<(User, Vec<Passkey>)>> {
        Err(not_supported("Retrieve user with passkeys"))
    }

    async fn list_projects(&self, user: &User) -> anyhow::Result<ListProjectsResult> {
        list_projects(user).await
    }

    async fn logout_session(&self, session: &Session) -> anyhow::Result<()> {
        let mut config = LocalServiceConfig::load()?;

        config.sessions.remove(&session.id);

        config.write()
    }

    async fn save_passkey(
        &self,
        _user: &User,
        _passkey_type: PasskeyType,
        _passkey_name: String,
        _cred_id: String,
        _public_key: String,
        _public_key_result: PublicKeyGenerateResult,
    ) -> anyhow::Result<Passkey> {
        Err(not_supported("Save passkey"))
    }

    async fn create_project(
        &self,
        user: &User,
        passkeys: &[Passkey],
        request: CreateProjectRequest,
    ) -> anyhow::Result<Project> {
        create_project(user, passkeys, request).await
    }

    async fn get_project_by_id(
        &self,
        user: &User,
        project_id: Uuid,
    ) -> anyhow::Result<Option<GetProjectResult>> {
        get_project_by_id(user, project_id).await
    }

    async fn get_environment_by_name(
        &self,
        user: &User,
        request: GetEnvironmentRequest,
    ) -> anyhow::Result<Option<GetEnvironmentResult>> {
        get_environment_by_name(user, &request).await
    }

    async fn create_secret(
        &self,
        user: &User,
        params: ProjectEnvPathParams,
        request: CreateSecretRequest,
    ) -> anyhow::Result<SecretWithEncryptedValues> {
        create_secret(user, params, request).await
    }

    async fn get_machine_secrets(
        &self,
        _params: GetMachineSecretParams,
    ) -> anyhow::Result<HashMap<String, String>> {
        Err(anyhow::anyhow!(
            "Secrets API not supported on local server. Use `spass local run/export`"
        ))
    }

    async fn create_machine_public_key(
        &self,
        user: &User,
        params: ProjectPathParams,
        request: CreateMachinePublicKeyRequest,
    ) -> anyhow::Result<MachinePublicKey> {
        create_machine_public_key(user, params.project_id, request).await
    }

    async fn update_secret(
        &self,
        user: &User,
        params: ProjectSecretPathParams,
        request: UpdateSecretRequest,
    ) -> anyhow::Result<SecretWithEncryptedValues> {
        update_secret(user, params, request).await
    }

    async fn update_secret_value(
        &self,
        user: &User,
        params: ProjectSecretPathParams,
        request: UpdateSecretValueRequest,
    ) -> anyhow::Result<SecretWithEncryptedValues> {
        update_secret_value(user, params, request).await
    }
}
