use crate::backend::projects::environments::environments_insert_query_builder;
use crate::backend::projects::passkeys::project_passkeys_insert_query_builder;
use secretpass_api::projects::{
    CreateProjectRequest, GetProjectResult, ListProjectsResult, ProjectListItem,
};
use secretpass_core::enums::ProjectUserStatus;
use secretpass_core::{
    ProjectUserLevel, SpassEnvironment, SpassPasskey, SpassProject, SpassProjectUser, SpassUser,
};
use sqlx::PgPool;
use uuid::Uuid;

// language=sql
const CREATE_PROJECT_QUERY: &str = r#"
    INSERT INTO "Projects" (name, description, algorithm)
    VALUES ($1, $2, $3)
    RETURNING *
"#;

// language=sql
const CREATE_PROJECT_USER_QUERY: &str = r#"
    INSERT INTO "ProjectUsers" (user_id, status, project_id, level, environments)
    VALUES ($1, $2, $3, $4, $5)
    RETURNING *
"#;

pub async fn create_project(
    pool: &PgPool,
    user: &SpassUser,
    passkeys: &[SpassPasskey],
    request: CreateProjectRequest,
) -> anyhow::Result<SpassProject> {
    let mut tx = pool.begin().await?;

    let project: SpassProject = sqlx::query_as(CREATE_PROJECT_QUERY)
        .bind(&request.name)
        .bind(&request.description)
        .bind(request.algorithm)
        .fetch_one(&mut *tx)
        .await?;

    environments_insert_query_builder(&project, &request.environments)
        .build()
        .execute(&mut *tx)
        .await?;

    sqlx::query(CREATE_PROJECT_USER_QUERY)
        .bind(user.id)
        .bind(ProjectUserStatus::Active)
        .bind(project.id)
        .bind(ProjectUserLevel::Admin)
        .bind(Vec::<String>::new())
        .execute(&mut *tx)
        .await?;

    project_passkeys_insert_query_builder(user, &project, passkeys)
        .build()
        .execute(&mut *tx)
        .await?;

    tx.commit().await?;

    Ok(project)
}

// language=sql
const LIST_PROJECTS_BY_USER_ID: &str = r#"
    SELECT project.* FROM "Projects" as project INNER JOIN "ProjectUsers" as users
    ON users.project_id = project.id
    WHERE users.user_id = $1
"#;

pub async fn list_projects(pool: &PgPool, user: &SpassUser) -> anyhow::Result<ListProjectsResult> {
    let projects: Vec<SpassProject> = sqlx::query_as(LIST_PROJECTS_BY_USER_ID)
        .bind(user.id)
        .fetch_all(pool)
        .await?;
    let projects = projects
        .iter()
        .map(|project| ProjectListItem {
            path: None,
            project: project.clone(),
        })
        .collect();

    Ok(ListProjectsResult {
        projects,
        inaccessible: vec![],
        pending: vec![],
        workspaces: vec![],
    })
}

// language=sql
const GET_PROJECT_BY_USER_ID: &str = r#"
    SELECT project.* FROM "Projects" as project INNER JOIN "ProjectUsers" as users
    ON users.project_id = project.id
    WHERE project.id = $1 AND users.user_id = $2
"#;

// language=sql
const GET_PROJECT_USER_BY_USER_ID: &str = r#"
    SELECT * FROM "ProjectUsers"
    WHERE project_id = $1 AND user_id = $2
"#;

// language=sql
const GET_ENVIRONMENTS_BY_PROJECT_ID: &str = r#"
    SELECT * FROM "Environments"
    WHERE project_id = $1
"#;

pub async fn get_project_by_id(
    pool: &PgPool,
    user: &SpassUser,
    project_id: Uuid,
) -> anyhow::Result<Option<GetProjectResult>> {
    let project: Option<SpassProject> = sqlx::query_as(GET_PROJECT_BY_USER_ID)
        .bind(project_id)
        .bind(user.id)
        .fetch_optional(pool)
        .await?;
    let project = match project {
        Some(result) => result,
        None => return Ok(None),
    };

    let project_user = match get_project_user_by_id(pool, user, project_id).await? {
        Some(pu) => pu,
        None => return Ok(None),
    };

    let environments: Vec<SpassEnvironment> = sqlx::query_as(GET_ENVIRONMENTS_BY_PROJECT_ID)
        .bind(project_id)
        .fetch_all(pool)
        .await?;

    let environments = environments
        .into_iter()
        .filter(|env| project_user.can_access(&env.name))
        .collect();

    Ok(Some(GetProjectResult {
        path: None,
        project,
        project_user,
        environments,
    }))
}

pub async fn get_project_user_by_id(
    pool: &PgPool,
    user: &SpassUser,
    project_id: Uuid,
) -> anyhow::Result<Option<SpassProjectUser>> {
    let project_user: Option<SpassProjectUser> = sqlx::query_as(GET_PROJECT_USER_BY_USER_ID)
        .bind(project_id)
        .bind(user.id)
        .fetch_optional(pool)
        .await?;

    Ok(project_user)
}
