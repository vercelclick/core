ALTER TABLE "ContributorSecretValues"
    DROP CONSTRAINT contributor_values_primary_key;

ALTER TABLE "ContributorSecretValues"
    ADD CONSTRAINT contributor_values_primary_key
        PRIMARY KEY (target, project_id, env_name, name, tag);


ALTER TABLE "MachineSecretValues"
    DROP CONSTRAINT machine_values_primary_key;

ALTER TABLE "MachineSecretValues"
    ADD CONSTRAINT machine_values_primary_key
        PRIMARY KEY (target, project_id, env_name, name, tag);