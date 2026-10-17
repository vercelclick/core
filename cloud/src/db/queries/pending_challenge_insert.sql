INSERT INTO "PendingChallenge"
    (owner, kind, value, generated_on)
    VALUES ($1, $2::"ChallengeKind", $3, now())
ON CONFLICT (owner, kind)
    DO UPDATE SET value = EXCLUDED.value, generated_on = EXCLUDED.generated_on
