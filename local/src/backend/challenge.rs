use std::sync::LazyLock;

use secretpass_api::backend::PendingChallenge;
use secretpass_core::enums::ChallengeKind;
use tokio::sync::Mutex;

struct ChallengeStore {
    challenge: Option<PendingChallenge>,
}

// Since this is local and every operation has to be approved by the user, we don't expect parallel operations
static CHALLENGE_STORE: LazyLock<Mutex<ChallengeStore>> =
    LazyLock::new(|| Mutex::new(ChallengeStore { challenge: None }));

pub async fn save_pending_challenge(challenge: &PendingChallenge) {
    let mut store = CHALLENGE_STORE.lock().await;
    store.challenge = Some(challenge.clone());
}

pub async fn get_pending_challenge(kind: ChallengeKind, owner: String) -> Option<PendingChallenge> {
    let mut store = CHALLENGE_STORE.lock().await;
    if let Some(pending) = store.challenge.clone() {
        store.challenge = None;

        if pending.kind != kind && pending.owner != owner {
            None
        } else {
            Some(pending)
        }
    } else {
        None
    }
}
