CREATE TYPE "EncryptionAlgorithm" as enum ('ECC', 'KEM', 'Hybrid');


CREATE TABLE "Projects"
(
    id          UUID PRIMARY KEY DEFAULT uuidv7(),
    name        TEXT,
    description TEXT,
    algorithm   "EncryptionAlgorithm",
    updated_at  TIMESTAMPTZ      DEFAULT now()
);


CREATE TYPE "ContributorRole" as enum ('Admin', 'Standard');

CREATE TYPE "ContributorStatus" as enum ('Active', 'Archived');

CREATE TABLE "Contributors"
(
    id           UUID PRIMARY KEY DEFAULT uuidv7(),
    user_id      UUID                NOT NULL,
    status       "ContributorStatus" NOT NULL,
    project_id   UUID                NOT NULL,
    role         "ContributorRole"   NOT NULL,
    environments TEXT[]              NOT NULL,
    updated_at   TIMESTAMPTZ      DEFAULT now(),

    CONSTRAINT fk_contributor_to_user
        FOREIGN KEY (user_id)
            REFERENCES "Users" (id)
            ON DELETE CASCADE,

    CONSTRAINT fk_contributor_to_project
        FOREIGN KEY (project_id)
            REFERENCES "Projects" (id)
            ON DELETE CASCADE
);

CREATE TYPE "AccessGrant" as enum ('Pending', 'Granted');

CREATE TABLE "ContributorPublicKeys"
(
    id             UUID PRIMARY KEY DEFAULT uuidv7(),
    name           TEXT          NOT NULL,
    user_id        UUID          NOT NULL,
    cred_id        TEXT          NOT NULL,
    contributor_id UUID          NOT NULL,
    access         "AccessGrant" NOT NULL,
    ecc            TEXT,
    kem            TEXT,
    granted_by     TEXT,
    granted_on     TIMESTAMPTZ,

    CONSTRAINT fk_contributor_pub_key_to_project
        FOREIGN KEY (contributor_id)
            REFERENCES "Contributors" (id)
            ON DELETE CASCADE,

    CONSTRAINT fk_contributor_pub_key_to_passkey
        FOREIGN KEY (user_id, cred_id)
            REFERENCES "Passkeys" (user_id, cred_id)
            ON DELETE CASCADE
);


CREATE TABLE "Environments"
(
    name        TEXT NOT NULL,
    project_id  UUID NOT NULL,
    description TEXT NOT NULL,
    tags        TEXT[]      DEFAULT '{}',
    created_at  TIMESTAMPTZ DEFAULT now(),
    updated_at  TIMESTAMPTZ DEFAULT now(),

    CONSTRAINT environments_primary_key
        PRIMARY KEY (project_id, name),
    CONSTRAINT fk_environment_project
        FOREIGN KEY (project_id)
            REFERENCES "Projects" (id)
            ON DELETE CASCADE
);


CREATE TABLE "SecretDefinitions"
(
    name       TEXT   NOT NULL,
    env_name   TEXT   NOT NULL,
    project_id UUID   NOT NULL,
    comments   TEXT   NOT NULL,
    tags       TEXT[] NOT NULL,
    created_at TIMESTAMPTZ DEFAULT now(),
    updated_at TIMESTAMPTZ DEFAULT now(),

    CONSTRAINT secret_definitions_primary_key
        PRIMARY KEY (project_id, env_name, name),
    CONSTRAINT fk_secret_definitions_environment
        FOREIGN KEY (project_id, env_name)
            REFERENCES "Environments" (project_id, name)
            ON DELETE CASCADE
);


CREATE TYPE "SecretDataType" as ENUM ('Text', 'Json', 'Url');

CREATE TABLE "ContributorSecretValues"
(
    name            TEXT NOT NULL,
    env_name        TEXT NOT NULL,
    target          UUID NOT NULL,
    project_id      UUID NOT NULL,
    tag             TEXT,
    data_type       "SecretDataType",
    encrypted_value TEXT,
    created_at      TIMESTAMPTZ DEFAULT now(),
    CONSTRAINT contributor_values_primary_key
        PRIMARY KEY (target, project_id, env_name, name),
    CONSTRAINT fk_contributor_values_definition
        FOREIGN KEY (project_id, env_name, name)
            REFERENCES "SecretDefinitions" (project_id, env_name, name)
            ON DELETE CASCADE,
    CONSTRAINT fk_contributor_value_to_public_key
        FOREIGN KEY (target)
            REFERENCES "ContributorPublicKeys" (id)
            ON DELETE CASCADE
);

CREATE TABLE "MachinePublicKeys"
(
    id           TEXT PRIMARY KEY,
    name         TEXT   NOT NULL,
    description  TEXT   NOT NULL,
    project_id   UUID   NOT NULL,
    environments TEXT[] NOT NULL,
    ecc          TEXT,
    kem          TEXT,
    generated_by TEXT   NOT NULL,
    generated_on TIMESTAMPTZ DEFAULT now(),

    CONSTRAINT fk_machine_public_key_project
        FOREIGN KEY (project_id)
            REFERENCES "Projects" (id)
            ON DELETE CASCADE
);


CREATE TABLE "MachineSecretValues"
(
    name            TEXT NOT NULL,
    env_name        TEXT NOT NULL,
    target          TEXT NOT NULL,
    project_id      UUID NOT NULL,
    tag             TEXT,
    data_type       "SecretDataType",
    encrypted_value TEXT,
    created_at      TIMESTAMPTZ DEFAULT now(),
    CONSTRAINT machine_values_primary_key
        PRIMARY KEY (target, project_id, env_name, name),
    CONSTRAINT fk_machine_values_definition
        FOREIGN KEY (project_id, env_name, name)
            REFERENCES "SecretDefinitions" (project_id, env_name, name)
            ON DELETE CASCADE,
    CONSTRAINT fk_machine_values_to_public_key
        FOREIGN KEY (target)
            REFERENCES "MachinePublicKeys" (id)
            ON DELETE CASCADE
);

