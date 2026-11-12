use click_core::WebauthnChallenge;
use click_core::enums::WebauthnChallengeKind;
use std::sync::LazyLock;
use tokio::sync::Mutex;

struct ChallengeStore {
    challenge: Option<WebauthnChallenge>,
}

// Since this is local and every operation has to be approved by the user, we don't expect parallel operations
static CHALLENGE_STORE: LazyLock<Mutex<ChallengeStore>> =
    LazyLock::new(|| Mutex::new(ChallengeStore { challenge: None }));

pub async fn save_challenge(challenge: &WebauthnChallenge) {
    let mut store = CHALLENGE_STORE.lock().await;
    store.challenge = Some(challenge.clone());
}

pub async fn get_challenge(kind: WebauthnChallengeKind, owner: &str) -> Option<WebauthnChallenge> {
    let mut store = CHALLENGE_STORE.lock().await;
    if let Some(challenge) = store.challenge.clone() {
        store.challenge = None;

        if challenge.kind != kind && challenge.owner != owner {
            None
        } else {
            Some(challenge)
        }
    } else {
        None
    }
}
