use rand::Rng;
use secretpass_core::utils::get_global_rng;
use secretpass_core::{InternalResult, KeyPair, PrivateKeySeed};

async fn create_seed_keys() -> ([u8; 32], [u8; 32]) {
    let mut rng = get_global_rng().lock().await;
    let mut seed_a = [0u8; 32];
    let mut seed_b = [0u8; 32];

    rng.fill_bytes(&mut seed_a);
    rng.fill_bytes(&mut seed_b);

    (seed_a, seed_b)
}

async fn create_same_seed_key() -> InternalResult<KeyPair> {
    let seed_keys = create_seed_keys().await;
    KeyPair::from_seed(PrivateKeySeed {
        first: seed_keys.0,
        second: seed_keys.1,
    })
}

#[tokio::test]
async fn test_encryption_decryption() {
    let private_key = create_same_seed_key().await.unwrap();
    let public_key = private_key.public_key();

    let original_payload = "Basic Elliptic-curve cryptography test".to_string();

    let encrypted_payload = public_key.encrypt(original_payload.clone()).await.unwrap();
    assert_ne!(
        original_payload, encrypted_payload,
        "encrypted payload cannot be equal to the clear payload"
    );

    let encrypted_payload_2 = public_key.encrypt(original_payload.clone()).await.unwrap();
    assert_ne!(
        encrypted_payload, encrypted_payload_2,
        "encrypted payload should change with every encryption run"
    );

    let decrypted_payload = match private_key.decrypt(&encrypted_payload) {
        Ok(payload) => payload,
        Err(err) => {
            panic!("What tha?: {:?}", err)
        }
    };

    assert_eq!(
        decrypted_payload, original_payload,
        "decrypted payload should be equal to the original payload"
    );

    let decrypted_payload_2 = private_key.decrypt(&encrypted_payload_2).unwrap();
    assert_eq!(
        decrypted_payload, decrypted_payload_2,
        "decrypted payload should never change between runs"
    );
}
