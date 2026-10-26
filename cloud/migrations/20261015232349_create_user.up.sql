CREATE TABLE "Users"
(
    id         UUID PRIMARY KEY,
    name       TEXT,
    email      TEXT UNIQUE,
    updated_at TIMESTAMPTZ DEFAULT NOW()
);


CREATE TYPE "PasskeyType" AS ENUM ('Local', 'Cloud');

CREATE TABLE "UserPasskeys"
(
    id         UUID PRIMARY KEY,
    user_id    UUID          NOT NULL,
    name       TEXT          NOT NULL,
    cred_id    TEXT          NOT NULL,
    "type"     "PasskeyType" NOT NULL,
    ecc        TEXT          NOT NULL,
    kem        TEXT          NOT NULL,
    public_key TEXT          NOT NULL,
    updated_at TIMESTAMPTZ DEFAULT now(),

    CONSTRAINT fk_passkey_user
        FOREIGN KEY (user_id)
            REFERENCES "Users" (id)
            ON DELETE CASCADE,
    CONSTRAINT unique_cred_id
        UNIQUE (cred_id, user_id)
);

CREATE TYPE "ChallengeKind" AS ENUM (
    'EmailSignup',
    'EmailSignIn',
    'PasskeySignup',
    'PasskeySignIn',
    'PasskeyAuthorize',
    'PasskeyCreate',
    'EmailAuthorize'
    );

-- If a challenge is lost, the user can simply create a new one
CREATE UNLOGGED TABLE "PendingChallenge"
(
    owner         TEXT,
    kind          "ChallengeKind",
    value_hash    TEXT,
    generated_on  TIMESTAMPTZ DEFAULT NOW(),
    attempts_left INT NOT NULL,

    PRIMARY KEY (owner, kind)
);

-- If a session is lost, the user can simply create a new one
CREATE UNLOGGED TABLE "UserSessions"
(
    id           UUID PRIMARY KEY DEFAULT uuidv7(),
    user_id      UUID NOT NULL,
    session_data JSONB,
    last_seen    TIMESTAMPTZ      DEFAULT NOW(),
    expires_on   TIMESTAMPTZ      DEFAULT (NOW() + INTERVAL '7 days'),

    CONSTRAINT fk_session_user
        FOREIGN KEY (user_id)
            REFERENCES "Users" (id)
            ON DELETE CASCADE
)