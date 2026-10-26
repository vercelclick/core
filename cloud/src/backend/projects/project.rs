use crate::backend::projects::environments::environments_insert_query_builder;
use crate::backend::projects::passkeys::project_passkeys_insert_query_builder;
use secretpass_api::projects::CreateProjectRequest;
use secretpass_core::enums::ProjectUserStatus;
use secretpass_core::{ProjectUserLevel, SpassPasskey, SpassProject, SpassUser};
use sqlx::PgPool;

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
