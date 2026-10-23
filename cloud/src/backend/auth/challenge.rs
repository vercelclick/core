use anyhow::Ok;
use secretpass_api::PendingChallenge;
use secretpass_core::enums::ChallengeKind;
use sqlx::{PgPool, Row};

// language=sql
const PENDING_CHALLENGE_INSERT: &str = r#"
    insert into "PendingChallenge"
        (owner, kind, value_hash, attempts_left)
        values ($1, $2::"ChallengeKind", $3)
    on conflict (owner, kind)
        do update set value_hash = EXCLUDED.value_hash, generated_on = now()
"#;

pub async fn insert_or_replace_challenge(
    pool: &PgPool,
    challenge: PendingChallenge,
) -> anyhow::Result<()> {
    sqlx::query(PENDING_CHALLENGE_INSERT)
        .bind(&challenge.owner)
        .bind(challenge.kind.to_string())
        .bind(&challenge.value_hash)
        .bind(&challenge.attempts_left)
        .execute(pool)
        .await?;

    Ok(())
}

// language=sql
const PENDING_CHALLENGE_POP: &str = r#"
    DELETE FROM "PendingChallenge" WHERE kind = $1::"ChallengeKind" AND owner = $2 RETURNING *
"#;

// language=sql
const PENDING_CHALLENGE_GET_ATTEMPT: &str = r#"
    UPDATE "PendingChallenge"
        SET attempts_left = (attempts_left - 1)
        WHERE attempts_left > 0 AND kind = $1::"ChallengeKind" AND owner = $2 RETURNING *
"#;

async fn query_pending_challenge(
    pool: &PgPool,
    query: &'static str,
    kind: ChallengeKind,
    owner: String,
) -> anyhow::Result<PendingChallenge> {
    let row = sqlx::query(query)
        .bind(kind.to_string())
        .bind(&owner)
        .fetch_one(pool)
        .await?;

    let challenge = PendingChallenge {
        kind,
        owner,
        value_hash: row.get("value_hash"),
        generated_on: row.get("generated_on"),
        attempts_left: row.get("attempts_left"),
    };

    Ok(challenge)
}

pub async fn pop_pending_challenge(
    pool: &PgPool,
    kind: ChallengeKind,
    owner: String,
) -> anyhow::Result<PendingChallenge> {
    query_pending_challenge(pool, PENDING_CHALLENGE_POP, kind, owner).await
}

pub async fn retrieve_pending_challenge_for_attempt(
    pool: &PgPool,
    kind: ChallengeKind,
    owner: String,
) -> anyhow::Result<PendingChallenge> {
    query_pending_challenge(pool, PENDING_CHALLENGE_GET_ATTEMPT, kind, owner).await
}
