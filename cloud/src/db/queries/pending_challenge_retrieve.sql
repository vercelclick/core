DELETE FROM "PendingChallenge" WHERE kind = $1::"ChallengeKind" AND value = $2 RETURNING *
