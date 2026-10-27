use crate::backend::projects::project::get_project_user_by_id;
use secretpass_api::environments::{
    GetEnvironmentRequest, GetEnvironmentResult, SecretWithEncryptedValues,
};
use secretpass_api::projects::CreateEnvironmentRequest;
use secretpass_core::{
    MachinePublicKey, PasskeySecretValue, ProjectUserPasskey, SecretDefinition, SpassEnvironment,
    SpassProject, SpassUser,
};
use sqlx::{PgPool, Postgres, QueryBuilder};

pub fn environments_insert_query_builder(
    project: &SpassProject,
    requests: &Vec<CreateEnvironmentRequest>,
) -> QueryBuilder<Postgres> {
    let mut query_builder: QueryBuilder<Postgres> =
        QueryBuilder::new(r#"INSERT INTO "Environments" (name, project_id, description) "#);

    query_builder.push_values(requests, |mut b, request| {
        b.push_bind(request.name.clone())
            .push_bind(project.id)
            .push_bind(request.description.clone());
    });

    query_builder.push(" RETURNING *");

    query_builder
}

pub async fn get_environment_by_name(
    pool: &PgPool,
    user: &SpassUser,
    request: &GetEnvironmentRequest,
) -> anyhow::Result<Option<GetEnvironmentResult>> {
    let project_user = match get_project_user_by_id(pool, user, request.project_id).await? {
        Some(pu) => pu,
        None => return Ok(None),
    };

    if !project_user.can_access(&request.env_name) {
        return Ok(None);
    }

    let environment: SpassEnvironment =
        sqlx::query_as(r#"SELECT * FROM "Environments" WHERE project_id = $1 AND name = $2"#)
            .bind(project_user.project_id)
            .bind(&request.env_name)
            .fetch_one(pool)
            .await?;

    let secret_definitions: Vec<SecretDefinition> = sqlx::query_as(
        r#"SELECT * FROM "SecretDefinitions" WHERE project_id = $1 AND env_name = $2"#,
    )
    .bind(project_user.project_id)
    .bind(&request.env_name)
    .fetch_all(pool)
    .await?;

    let secret_passkey_values: Vec<PasskeySecretValue> = sqlx::query_as(
        r#"SELECT psv.* FROM "PasskeySecretValues" psv
                     INNER JOIN "ProjectUserPasskey" pup ON pup.id = psv.passkey_id
                     WHERE pup.user_id = $1 AND psv.env_name = $2"#,
    )
    .bind(project_user.user_id)
    .bind(&request.env_name)
    .fetch_all(pool)
    .await?;

    let passkeys: Vec<ProjectUserPasskey> = sqlx::query_as(
        r#"SELECT pup.* FROM "ProjectUserPasskey" pup
                    INNER JOIN "ProjectUsers" pu ON pu.id = pup.user_id
                    WHERE pu.project_id = $1 AND (pu.level = 'Admin' OR $2 = ANY(pu.environments))"#,
    )
    .bind(project_user.project_id)
    .bind(&request.env_name)
    .fetch_all(pool)
    .await?;

    let machines: Vec<MachinePublicKey> = sqlx::query_as(
        r#"SELECT * FROM "MachinePublicKey" WHERE project_id = $1 AND $2 = ANY(environments)"#,
    )
    .bind(project_user.project_id)
    .bind(&request.env_name)
    .fetch_all(pool)
    .await?;

    let secrets: Vec<SecretWithEncryptedValues> = secret_definitions
        .iter()
        .map(|definition| SecretWithEncryptedValues::extract(definition, &secret_passkey_values))
        .collect();

    Ok(Some(GetEnvironmentResult {
        environment,
        secrets,
        passkeys,
        machines,
    }))
}
