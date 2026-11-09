use chrono::Utc;
use secretpass_api::constants::LATEST_SECRET_TAG;
use secretpass_core::{ContributorSecretValue, MachineSecretValue, SecretValue};
use uuid::Uuid;

pub fn build_latest_attributed_values(
    project_id: Uuid,
    encrypted_values: &[SecretValue],
) -> (Vec<ContributorSecretValue>, Vec<MachineSecretValue>) {
    let mut machine_values: Vec<MachineSecretValue> = Vec::new();
    let mut contributor_values: Vec<ContributorSecretValue> = Vec::new();

    for value in encrypted_values {
        let id_version = value.target.get_version_num();

        if id_version == 5 {
            machine_values.push(MachineSecretValue {
                name: value.name.clone(),
                tag: LATEST_SECRET_TAG.to_string(),
                encrypted_value: value.encrypted_value.clone(),
                env_name: value.environment.clone(),
                project_id,
                created_at: Utc::now(),
                data_type: value.data_type,
                target: value.target,
            });
        } else if id_version == 7 {
            contributor_values.push(ContributorSecretValue {
                name: value.name.clone(),
                tag: LATEST_SECRET_TAG.to_string(),
                encrypted_value: value.encrypted_value.clone(),
                env_name: value.environment.clone(),
                project_id,
                created_at: Utc::now(),
                data_type: value.data_type,
                target: value.target,
            });
        }
    }

    (contributor_values, machine_values)
}
