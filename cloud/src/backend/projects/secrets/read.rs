use secretpass_core::SecretDefinition;
use sqlx::PgPool;
use uuid::Uuid;

pub async fn get_secret_by_name(
    pool: &PgPool,
    project_id: Uuid,
    env_name: &str,
    secret_name: &str,
) -> anyhow::Result<Option<SecretDefinition>> {
    let definition: Option<SecretDefinition> = sqlx::query_as(
        r#"SELECT * FROM "SecretDefinitions" WHERE project_id=$1 AND env_name=$2 AND name=$3"#,
    )
    .bind(project_id)
    .bind(env_name)
    .bind(secret_name)
    .fetch_optional(pool)
    .await?;

    Ok(definition)
}
