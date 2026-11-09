use secretpass_api::PendingChallenge;
use secretpass_core::enums::ChallengeKind;
use secretpass_core::{InternalError, InternalResult, StatusCode, source};
use sqlx::{PgPool, Row};

// language=sql
const PENDING_CHALLENGE_INSERT: &str = r#"
    insert into "PendingChallenge"
        (owner, kind, value_hash, attempts_left)
        values ($1, $2, $3, $4)
    on conflict (owner, kind)
        do update set value_hash = EXCLUDED.value_hash, attempts_left = EXCLUDED.attempts_left, generated_on = now()
"#;

pub async fn insert_or_replace_challenge(
    pool: &PgPool,
    challenge: &PendingChallenge,
) -> InternalResult<()> {
    sqlx::query(PENDING_CHALLENGE_INSERT)
        .bind(&challenge.owner)
        .bind(challenge.kind)
        .bind(&challenge.value_hash)
        .bind(challenge.attempts_left)
        .execute(pool)
        .await
        .map_err(|err| {
            InternalError::trace(
                source!(),
                StatusCode::INTERNAL_SERVER_ERROR,
                &format!("Internal error creating {} challenge", challenge.kind),
                err,
            )
        })?;

    Ok(())
}

// language=sql
const PENDING_CHALLENGE_GET: &str = r#"
    SELECT * FROM "PendingChallenge" WHERE kind = $1 AND owner = $2
"#;

// language=sql
const PENDING_CHALLENGE_ATTEMPT: &str = r#"
    UPDATE "PendingChallenge"
        SET attempts_left = (attempts_left - 1)
        WHERE attempts_left > 0 AND kind = $1 AND owner = $2 RETURNING *
"#;

async fn query_pending_challenge(
    pool: &PgPool,
    query: &'static str,
    kind: ChallengeKind,
    owner: String,
) -> InternalResult<Option<PendingChallenge>> {
    let row = sqlx::query(query)
        .bind(kind)
        .bind(&owner)
        .fetch_optional(pool)
        .await
        .map_err(|err| {
            InternalError::trace(
                source!(),
                StatusCode::INTERNAL_SERVER_ERROR,
                &format!("Internal error getting {kind} challenge"),
                err,
            )
        })?;

    let row = match row {
        Some(row) => row,
        None => return Ok(None),
    };

    let challenge = PendingChallenge {
        kind,
        owner,
        value_hash: row.get("value_hash"),
        generated_on: row.get("generated_on"),
        attempts_left: row.get("attempts_left"),
    };

    Ok(Some(challenge))
}

pub async fn get_pending_challenge(
    pool: &PgPool,
    kind: ChallengeKind,
    owner: String,
) -> InternalResult<Option<PendingChallenge>> {
    query_pending_challenge(pool, PENDING_CHALLENGE_GET, kind, owner).await
}

pub async fn retrieve_pending_challenge_for_attempt(
    pool: &PgPool,
    kind: ChallengeKind,
    owner: String,
) -> InternalResult<Option<PendingChallenge>> {
    query_pending_challenge(pool, PENDING_CHALLENGE_ATTEMPT, kind, owner).await
}
