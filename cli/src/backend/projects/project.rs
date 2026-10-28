use crate::config::LocalServiceConfig;
use crate::service::keys::LocalKeysConfig;
use crate::service::project::LocalProjectConfig;
use crate::utils::short_path;
use chrono::Utc;
use secretpass_api::projects::{
    CreateProjectRequest, GetProjectResult, ListProjectsResult, ProjectListItem, ProjectPath,
};
use secretpass_core::enums::{AccessGrant, ProjectUserStatus};
use secretpass_core::{
    ProjectUserLevel, ProjectUserPasskey, SpassEnvironment, SpassPasskey, SpassProject,
    SpassProjectUser, SpassUser,
};
use uuid::Uuid;

pub async fn list_projects(user: &SpassUser) -> anyhow::Result<ListProjectsResult> {
    let mut config = LocalServiceConfig::load()?;

    let mut should_update = false;
    let mut result = ListProjectsResult {
        projects: vec![],
        pending: vec![],
        inaccessible: vec![],
        workspaces: vec![],
    };

    for project_path in config.known_projects.clone() {
        let path = ProjectPath {
            path: project_path.clone(),
            short_path: short_path(&project_path),
        };
        if let Some(project_config) = LocalProjectConfig::load(&project_path)? {
            let project_id = project_config.project.id;
            let item = ProjectListItem {
                path: Some(path),
                project: project_config.project.clone(),
            };
            if project_config.get_user(user.id).is_some() {
                result.projects.push(item);
            } else {
                result.inaccessible.push(item);
            }

            if config.attach(&project_path, project_id) {
                should_update = true;
            }
        } else {
            result.pending.push(path);
        }
    }

    if should_update {
        config.write()?;
    }

    Ok(result)
}

pub async fn create_project(
    user: &SpassUser,
    passkeys: &[SpassPasskey],
    request: CreateProjectRequest,
) -> anyhow::Result<SpassProject> {
    let mut config = LocalServiceConfig::load()?;

    let path = request
        .path
        .ok_or_else(|| anyhow::anyhow!("A path is required when creating a secretpass project"))?;

    if let Some(project_config) = LocalProjectConfig::load(&path)? {
        if config.attach(&path, project_config.project.id) {
            config.write()?;
        }

        return Err(anyhow::format_err!(
            "A project({}) already exists under {}. Please delete .spass directory if you intend to replace the project.",
            project_config.project.name,
            short_path(&path)
        ));
    }

    let project = SpassProject {
        id: Uuid::now_v7(),
        algorithm: request.algorithm,
        name: request.name.clone(),
        description: request.description.clone(),
        updated_at: Utc::now(),
    };

    let environments: Vec<SpassEnvironment> = request
        .environments
        .iter()
        .map(|env| SpassEnvironment {
            name: env.name.clone(),
            project_id: project.id,
            created_at: Utc::now(),
            updated_at: Utc::now(),
            description: env.description.clone(),
            tags: vec![],
        })
        .collect();

    let project_user = SpassProjectUser {
        id: Uuid::now_v7(),
        project_id: project.id,
        user_id: user.id,
        status: ProjectUserStatus::Active,
        level: ProjectUserLevel::Admin,
        environments: vec![],
        updated_at: Utc::now(),
    };

    let passkeys = passkeys
        .iter()
        .map(|passkey| ProjectUserPasskey {
            id: Uuid::now_v7(),
            name: format!("{} - {}", user.email, passkey.name),
            user_id: project_user.id,
            ecc: request.algorithm.is_ecc().then_some(passkey.ecc.clone()),
            kem: request.algorithm.is_kem().then_some(passkey.kem.clone()),
            passkey_id: passkey.id,
            access: AccessGrant::Granted,
            granted_by: Some(user.email.clone()),
            granted_on: Some(Utc::now()),
        })
        .collect();

    let project_conf = LocalProjectConfig {
        project: project.clone(),
        environments,
        users: vec![(user.clone(), project_user)],
    };

    let keys_conf = LocalKeysConfig {
        passkeys,
        machines: vec![],
    };

    project_conf.write(&path)?;
    keys_conf.write(&path)?;

    if config.attach(&path, project.id) {
        config.write()?;
    }

    Ok(project)
}

pub async fn get_project_by_id(
    user: &SpassUser,
    project_id: Uuid,
) -> anyhow::Result<Option<GetProjectResult>> {
    let config = LocalServiceConfig::load()?;

    let (path, project_config) = match config.get_project_by_id(project_id)? {
        Some(result) => result,
        None => return Ok(None),
    };

    let project_user = project_config.get_user(user.id).ok_or_else(|| {
        anyhow::format_err!(
            "FORBIDDEN: you do not have access to this project under {}",
            user.email
        )
    })?;

    Ok(Some(GetProjectResult {
        project: project_config.project,
        project_user,
        environments: project_config.environments,
        path: Some(ProjectPath {
            path: path.clone(),
            short_path: short_path(&path),
        }),
    }))
}
