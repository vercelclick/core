use crate::passkeys::prf::PrfResults;
use secretpass_core::enums::SecretDataType;
use secretpass_core::{
    ContributorSecretValue, InternalResult, KeyPair, PrivateKeySeed, PublicKey, SecretValue,
    TargetedPublicKey,
};

#[derive(Clone)]
pub struct SecureSession {
    private_key: KeyPair,
}

impl SecureSession {
    pub fn new(prf_results: PrfResults) -> InternalResult<Self> {
        let seed = PrivateKeySeed {
            first: prf_results.first,
            second: prf_results.second,
        };

        let private_key = KeyPair::from_seed(seed)?;

        Ok(Self { private_key })
    }

    pub fn decrypt(&self, cipher: &str) -> InternalResult<String> {
        self.private_key.decrypt(cipher)
    }

    pub fn public_key(&self) -> PublicKey {
        self.private_key.public_key()
    }

    pub async fn reencrypt_value(
        &self,
        value: &ContributorSecretValue,
        keys: &[TargetedPublicKey],
    ) -> InternalResult<Vec<SecretValue>> {
        let plain_value = self.decrypt(&value.encrypted_value)?;

        let mut encrypted_values = Vec::<SecretValue>::with_capacity(keys.len());
        for key in keys {
            let encrypted_value = key.public_key()?.encrypt(plain_value.clone()).await?;

            encrypted_values.push(SecretValue {
                tag: value.tag.clone(),
                name: value.name.clone(),
                environment: value.env_name.clone(),
                encrypted_value,
                data_type: SecretDataType::Text,
                target: key.target,
            })
        }

        Ok(encrypted_values)
    }
}
