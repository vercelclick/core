use secretpass_core::{EncryptionAlgorithm, SpassProject, SpassWorkspace};
use secretpass_web::PasskeyAuthorizationResult;
use serde::{Deserialize, Serialize};
use ts_rs::TS;

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct ProjectPath {
    pub path: String,
    pub short_path: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct ProjectListItem {
    pub project: SpassProject,
    pub path: Option<ProjectPath>,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct WorkspaceProjectListItem {
    pub workspace: SpassWorkspace,
    pub projects: Vec<SpassProject>,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct ListProjectsResult {
    pub pending: Vec<ProjectPath>,
    pub projects: Vec<ProjectListItem>,
    pub workspaces: Vec<WorkspaceProjectListItem>,
    pub inaccessible: Vec<ProjectListItem>,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct CreateEnvironmentRequest {
    pub name: String,
    pub description: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct CreateProjectRequest {
    pub path: Option<String>,
    pub name: String,
    pub description: String,
    pub algorithm: EncryptionAlgorithm,
    pub environments: Vec<CreateEnvironmentRequest>,
    pub auth_response: PasskeyAuthorizationResult,
}
