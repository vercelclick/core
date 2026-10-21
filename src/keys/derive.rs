use crate::enums::EncryptionAlgorithm;
use crate::utils::{bin_deserialize, bin_serialize, get_global_rng};
use argon2::Argon2;
pub(crate) use ml_kem::ml_kem_768::{
    DecapsulationKey as KemPrivateKey, EncapsulationKey as KemPublicKey,
};
use ml_kem::{FromSeed, MlKem768, Seed};
use rand::Rng;
use serde::{Deserialize, Serialize};
pub(crate) use x25519_dalek::{PublicKey as EccPublicKey, StaticSecret as EccPrivateKey};

#[derive(Clone, Serialize, Deserialize)]
struct MachineKey([u8; 32], [u8; 32]);

#[derive(Clone, Deserialize)]
pub struct PrivateKeySeed {
    pub algorithm: EncryptionAlgorithm,
    pub first: [u8; 32],
    pub second: [u8; 32],
}

impl PrivateKeySeed {
    pub fn derive_ecc_keys(&self) -> anyhow::Result<(EccPublicKey, EccPrivateKey)> {
        let mut seed = [0u8; 32];

        Argon2::default().hash_password_into(&self.first, &self.second, &mut seed)?;

        let private_key = EccPrivateKey::from(seed);
        let public_key = EccPublicKey::from(&private_key);

        Ok((public_key, private_key))
    }

    pub fn derive_kem_keys(&self) -> anyhow::Result<(KemPublicKey, KemPrivateKey)> {
        let mut seed_bytes = [0u8; 64];
        seed_bytes[..32].copy_from_slice(&self.first);
        seed_bytes[32..].copy_from_slice(&self.second);

        let seed = Seed::try_from(seed_bytes)
            .map_err(|_| anyhow::anyhow!("Error parsing KEM key seed"))?;
        let (private_key, public_key) = MlKem768::from_seed(&seed);

        Ok((public_key, private_key))
    }

    pub fn generate_machine_key(algorithm: EncryptionAlgorithm) -> anyhow::Result<(String, Self)> {
        let mut rng = get_global_rng().lock().unwrap();

        let mut first = [0u8; 32];
        rng.fill_bytes(&mut first);

        let mut second = [0u8; 32];
        rng.fill_bytes(&mut second);

        let machine_key = MachineKey(first, second);
        let encoded = bin_serialize(&machine_key)?;
        let seed = Self {
            algorithm,
            first,
            second,
        };
        Ok((encoded, seed))
    }

    pub fn from_machine_key(
        algorithm: EncryptionAlgorithm,
        encoded: String,
    ) -> anyhow::Result<Self> {
        let machine_key: MachineKey = bin_deserialize(&encoded)?;
        Ok(Self {
            algorithm,
            first: machine_key.0,
            second: machine_key.1,
        })
    }
}
