use crate::backend::projects::project::get_contributor_by_id;
use secretpass_api::environments::{
    GetEnvironmentRequest, GetEnvironmentResult, SecretWithEncryptedValues,
};
use secretpass_api::projects::CreateEnvironmentRequest;
use secretpass_core::{
    ContributorPublicKey, ContributorSecretValue, Environment, MachinePublicKey, Project,
    SecretDefinition, User,
};
use sqlx::{PgPool, Postgres, QueryBuilder};
use uuid::Uuid;

pub fn environments_insert_query_builder(
    project: &Project,
    requests: &Vec<CreateEnvironmentRequest>,
) -> QueryBuilder<Postgres> {
    // language=sql
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
    project_id: Uuid,
    env_name: &str,
) -> anyhow::Result<Option<Environment>> {
    let environment: Option<Environment> =
        sqlx::query_as(r#"SELECT * FROM "Environments" WHERE project_id = $1 AND name = $2"#)
            .bind(project_id)
            .bind(env_name)
            .fetch_optional(pool)
            .await?;

    Ok(environment)
}

pub async fn get_environment_handler(
    pool: &PgPool,
    user: &User,
    request: &GetEnvironmentRequest,
) -> anyhow::Result<Option<GetEnvironmentResult>> {
    let contributor = match get_contributor_by_id(pool, user, request.project_id).await? {
        Some(pu) => pu,
        None => return Ok(None),
    };

    if !contributor.can_access(&request.env_name) {
        return Ok(None);
    }

    let environment = get_environment_by_name(pool, contributor.project_id, &request.env_name)
        .await?
        .ok_or_else(|| anyhow::anyhow!("Environment not found"))?;

    let secret_definitions: Vec<SecretDefinition> = sqlx::query_as(
        r#"SELECT * FROM "SecretDefinitions" WHERE project_id = $1 AND env_name = $2"#,
    )
    .bind(contributor.project_id)
    .bind(&request.env_name)
    .fetch_all(pool)
    .await?;

    let contributor_secret_values: Vec<ContributorSecretValue> = sqlx::query_as(
        r#"SELECT psv.* FROM "ContributorSecretValues" psv
                     INNER JOIN "ContributorPublicKeys" cpk ON cpk.id = psv.target
                     WHERE cpk.contributor_id = $1 AND psv.env_name = $2"#,
    )
    .bind(contributor.id)
    .bind(&request.env_name)
    .fetch_all(pool)
    .await?;

    let contributors_keys: Vec<ContributorPublicKey> = sqlx::query_as(
        r#"SELECT cpk.* FROM "ContributorPublicKeys" cpk
                    INNER JOIN "Contributors" contributor ON contributor.id = cpk.contributor_id
                    WHERE contributor.project_id = $1 AND (contributor.role = 'Admin' OR $2 = ANY(contributor.environments))"#,
    )
    .bind(contributor.project_id)
    .bind(&request.env_name)
    .fetch_all(pool)
    .await?;

    let machines_keys: Vec<MachinePublicKey> = sqlx::query_as(
        r#"SELECT * FROM "MachinePublicKeys" WHERE project_id = $1 AND $2 = ANY(environments)"#,
    )
    .bind(contributor.project_id)
    .bind(&request.env_name)
    .fetch_all(pool)
    .await?;

    let current_contributor_keys: Vec<ContributorPublicKey> = contributors_keys
        .iter()
        .filter(|c| c.contributor_id == contributor.id)
        .cloned()
        .collect();

    let secrets: Vec<SecretWithEncryptedValues> = secret_definitions
        .iter()
        .map(|definition| {
            SecretWithEncryptedValues::extract(
                definition,
                &current_contributor_keys,
                &contributor_secret_values,
            )
        })
        .collect();

    Ok(Some(GetEnvironmentResult {
        environment,
        secrets,
        contributors_keys,
        machines_keys,
    }))
}
