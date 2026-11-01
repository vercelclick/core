use rand::Rng;
use secretpass_core::enums::EncryptionAlgorithm;
use secretpass_core::utils::get_global_rng;
use secretpass_core::{PrivateKey, PrivateKeySeed, PublicKeyEncrypt};

fn create_seed_keys() -> ([u8; 32], [u8; 32]) {
    let mut rng = get_global_rng().lock().unwrap();
    let mut seed_a = [0u8; 32];
    let mut seed_b = [0u8; 32];

    rng.fill_bytes(&mut seed_a);
    rng.fill_bytes(&mut seed_b);

    (seed_a, seed_b)
}

fn create_same_seed_key() -> anyhow::Result<PrivateKey> {
    let seed_keys = create_seed_keys();
    PrivateKey::from_seed(PrivateKeySeed {
        first: seed_keys.0,
        second: seed_keys.1,
    })
}

#[test]
fn test_ecc_encryption_decryption() {
    let private_key = create_same_seed_key().unwrap();

    let original_payload = "Basic Elliptic-curve cryptography test".to_string();

    let encrypted_payload = private_key
        .public_key(EncryptionAlgorithm::ECC)
        .encrypt(original_payload.clone())
        .unwrap();
    assert_ne!(
        original_payload, encrypted_payload,
        "encrypted payload cannot be equal to the clear payload"
    );
    assert_ne!(
        encrypted_payload,
        private_key
            .public_key(EncryptionAlgorithm::ECC)
            .encrypt(original_payload.clone())
            .unwrap(),
        "encrypted payload should change with every encryption run"
    );

    let decrypted_payload = private_key.decrypt(&encrypted_payload).unwrap();
    assert_eq!(
        decrypted_payload, original_payload,
        "decrypted payload should be equal to the original payload"
    );
}

#[test]
fn test_kem_encryption_decryption() {
    let private_key = create_same_seed_key().unwrap();

    let original_payload = "Basic Key-Encapsulation Mechanism cryptography test".to_string();

    let encrypted_payload = private_key
        .public_key(EncryptionAlgorithm::KEM)
        .encrypt(original_payload.clone())
        .unwrap();
    assert_ne!(
        original_payload, encrypted_payload,
        "encrypted payload cannot be equal to the clear payload"
    );
    assert_ne!(
        encrypted_payload,
        private_key
            .public_key(EncryptionAlgorithm::KEM)
            .encrypt(original_payload.clone())
            .unwrap(),
        "encrypted payload should change with every encryption run"
    );

    let decrypted_payload = private_key.decrypt(&encrypted_payload).unwrap();
    assert_eq!(
        decrypted_payload, original_payload,
        "decrypted payload should be equal to the original payload"
    );
}

#[test]
fn test_hybrid_encryption_decryption() {
    let private_key = create_same_seed_key().unwrap();

    let original_payload = "Basic Key-Encapsulation Mechanism cryptography test".to_string();

    let encrypted_payload = private_key
        .public_key(EncryptionAlgorithm::Hybrid)
        .encrypt(original_payload.clone())
        .unwrap();
    assert_ne!(
        original_payload, encrypted_payload,
        "encrypted payload cannot be equal to the clear payload"
    );
    assert_ne!(
        encrypted_payload,
        private_key
            .public_key(EncryptionAlgorithm::Hybrid)
            .encrypt(original_payload.clone())
            .unwrap(),
        "encrypted payload should change with every encryption run"
    );

    let decrypted_payload = private_key.decrypt(&encrypted_payload).unwrap();
    assert_eq!(
        decrypted_payload, original_payload,
        "decrypted payload should be equal to the original payload"
    );
}
