use secretpass_api::secrets::GetMachineSecretParams;
use secretpass_core::{MachinePublicKey, MachineSecretValue, SecretDefinition};
use sqlx::PgPool;
use std::collections::HashMap;
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

pub async fn get_machine_secrets(
    pool: &PgPool,
    params: GetMachineSecretParams,
) -> anyhow::Result<HashMap<String, String>> {
    let machine_key: Option<MachinePublicKey> = sqlx::query_as(
        r#"SELECT * FROM "MachinePublicKeys"
         WHERE project_id = $1 AND (id = $2 OR id = $3 OR id = $4)"#,
    )
    .bind(&params.project_id)
    .bind(&params.key_a)
    .bind(&params.key_b)
    .bind(&params.key_c)
    .fetch_optional(pool)
    .await?;

    let machine_key = machine_key.ok_or_else(|| anyhow::anyhow!("Public key not found"))?;
    machine_key
        .can_access(&params.env_name)
        .ok_or_else(|| anyhow::format_err!("Key does not have access to {}", params.env_name))?;

    let values: Vec<MachineSecretValue> = sqlx::query_as(
        r#"SELECT * FROM "MachineSecretValues"
         WHERE project_id = $1 AND target = $2 AND env_name = $3 AND tag = $4"#,
    )
    .bind(machine_key.project_id)
    .bind(machine_key.id)
    .bind(&params.env_name)
    .bind(&params.tag_name)
    .fetch_all(pool)
    .await?;

    let mut encrypted_secrets: HashMap<String, String> = HashMap::new();
    for value in values {
        encrypted_secrets.insert(value.name, value.encrypted_value);
    }

    Ok(encrypted_secrets)
}
