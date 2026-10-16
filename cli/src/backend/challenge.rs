use secretpass_api::PendingChallenge;
use secretpass_core::enums::ChallengeKind;
use tokio::sync::Mutex;

// Since this is local and every operation has to be approved by the user, we don't expect parallel operations
static PENDING_CHALLENGE: Mutex<Option<PendingChallenge>> = Mutex::new(None);

pub async fn save_pending_challenge(challenge: PendingChallenge) {
    let mut pending_challenge = PENDING_CHALLENGE.lock().await;
    *pending_challenge = Some(challenge);
}

pub async fn get_pending_challenge(
    kind: ChallengeKind,
    challenge: String,
) -> Option<PendingChallenge> {
    let mut pending_challenge = PENDING_CHALLENGE.lock().await;
    if let Some(pending) = pending_challenge.clone() {
        *pending_challenge = None;
        if pending.kind != kind && pending.value != challenge {
            None
        } else {
            Some(pending)
        }
    } else {
        None
    }
}
