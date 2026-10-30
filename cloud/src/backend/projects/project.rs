use crate::backend::projects::environments::environments_insert_query_builder;
use crate::backend::projects::passkeys::contributor_public_key_insert_query_builder;
use secretpass_api::projects::{
    CreateProjectRequest, GetProjectResult, ListProjectsResult, ProjectListItem,
};
use secretpass_core::enums::{ContributorRole, ContributorStatus};
use secretpass_core::{Contributor, Environment, Passkey, Project, User};
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
    INSERT INTO "Contributors" (user_id, status, project_id, role, environments)
    VALUES ($1, $2, $3, $4, $5)
    RETURNING *
"#;

pub async fn create_project(
    pool: &PgPool,
    user: &User,
    passkeys: &[Passkey],
    request: CreateProjectRequest,
) -> anyhow::Result<Project> {
    let mut tx = pool.begin().await?;

    let project: Project = sqlx::query_as(CREATE_PROJECT_QUERY)
        .bind(&request.name)
        .bind(&request.description)
        .bind(request.algorithm)
        .fetch_one(&mut *tx)
        .await?;

    environments_insert_query_builder(&project, &request.environments)
        .build()
        .execute(&mut *tx)
        .await?;

    let contributor: Contributor = sqlx::query_as(CREATE_PROJECT_USER_QUERY)
        .bind(user.id)
        .bind(ContributorStatus::Active)
        .bind(project.id)
        .bind(ContributorRole::Admin)
        .bind(Vec::<String>::new())
        .fetch_one(&mut *tx)
        .await?;

    contributor_public_key_insert_query_builder(user, &contributor, &project, passkeys)
        .build()
        .execute(&mut *tx)
        .await?;

    tx.commit().await?;

    Ok(project)
}

// language=sql
const LIST_PROJECTS_BY_USER_ID: &str = r#"
    SELECT project.* FROM "Projects" as project INNER JOIN "Contributors" as users
    ON users.project_id = project.id
    WHERE users.user_id = $1
"#;

pub async fn list_projects(pool: &PgPool, user: &User) -> anyhow::Result<ListProjectsResult> {
    let projects: Vec<Project> = sqlx::query_as(LIST_PROJECTS_BY_USER_ID)
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
const GET_PROJECT_BY_CONTRIBUTOR_ID: &str = r#"
    SELECT project.* FROM "Projects" as project INNER JOIN "Contributors" as contributor
    ON contributor.project_id = project.id
    WHERE project.id = $1 AND contributor.user_id = $2
"#;

// language=sql
const GET_CONTRIBUTOR_BY_USER_ID: &str = r#"
    SELECT * FROM "Contributors"
    WHERE project_id = $1 AND user_id = $2
"#;

// language=sql
const GET_ENVIRONMENTS_BY_PROJECT_ID: &str = r#"
    SELECT * FROM "Environments"
    WHERE project_id = $1
"#;

pub async fn get_project_by_id(
    pool: &PgPool,
    user: &User,
    project_id: Uuid,
) -> anyhow::Result<Option<GetProjectResult>> {
    let project: Option<Project> = sqlx::query_as(GET_PROJECT_BY_CONTRIBUTOR_ID)
        .bind(project_id)
        .bind(user.id)
        .fetch_optional(pool)
        .await?;
    let project = match project {
        Some(result) => result,
        None => return Ok(None),
    };

    let contributor = match get_contributor_by_id(pool, user, project_id).await? {
        Some(pu) => pu,
        None => return Ok(None),
    };

    let environments: Vec<Environment> = sqlx::query_as(GET_ENVIRONMENTS_BY_PROJECT_ID)
        .bind(project_id)
        .fetch_all(pool)
        .await?;

    let environments = environments
        .into_iter()
        .filter(|env| contributor.can_access(&env.name))
        .collect();

    Ok(Some(GetProjectResult {
        path: None,
        project,
        contributor,
        environments,
    }))
}

pub async fn get_contributor_by_id(
    pool: &PgPool,
    user: &User,
    project_id: Uuid,
) -> anyhow::Result<Option<Contributor>> {
    let contributor: Option<Contributor> = sqlx::query_as(GET_CONTRIBUTOR_BY_USER_ID)
        .bind(project_id)
        .bind(user.id)
        .fetch_optional(pool)
        .await?;

    Ok(contributor)
}
