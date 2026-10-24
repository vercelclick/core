use crate::config::LocalServiceConfig;
use crate::service::project::LocalProjectConfig;
use crate::utils::short_path;
use secretpass_api::projects::{ListProjectsResult, ProjectListItem, ProjectPath};
use secretpass_core::SecretpassUser;

pub async fn list_projects(user: &SecretpassUser) -> anyhow::Result<ListProjectsResult> {
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
            short_path: short_path(project_path.clone()),
        };
        if let Some(project_config) = LocalProjectConfig::load(&project_path)? {
            let project_id = project_config.project.id;
            let item = ProjectListItem {
                path: Some(path),
                project: project_config.project.clone(),
            };
            if project_config.user_has_access(user.id) {
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
