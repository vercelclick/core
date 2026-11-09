use crate::result::{InternalError, InternalResult};
use crate::source;
use crate::utils::{bin_decode, bin_encode, fill_random_bytes};
use argon2::Argon2;
use http::StatusCode;
use serde::Deserialize;
use uuid::Uuid;
pub(crate) use x25519_dalek::{PublicKey as DerivedPublicKey, StaticSecret as DerivedPrivateKey};

struct DirectAccessKey {
    project_id: Uuid,
    first: [u8; 32],
    second: [u8; 32],
}

impl DirectAccessKey {
    fn encode(&self) -> String {
        let project_id: [u8; 16] = self.project_id.into_bytes();

        let key = [&project_id[..], &self.first[..], &self.second[..]];
        let key: Vec<u8> = key.concat();
        bin_encode(&key)
    }

    fn decode(key: &str) -> InternalResult<Self> {
        let key = bin_decode(key)?;

        if key.len() != 80 {
            return Err(InternalError::new(
                source!(),
                StatusCode::BAD_REQUEST,
                "Invalid direct access key format",
            ));
        }

        let project_id = &key[..16];
        let first = &key[16..48];
        let second = &key[48..];

        Ok(Self {
            project_id: Uuid::from_bytes(project_id.try_into().map_err(|err| {
                InternalError::trace(
                    source!(),
                    StatusCode::BAD_REQUEST,
                    "Invalid project ID",
                    err,
                )
            })?),
            first: first.try_into().map_err(|err| {
                InternalError::trace(
                    source!(),
                    StatusCode::BAD_REQUEST,
                    "Invalid private seed value",
                    err,
                )
            })?,
            second: second.try_into().map_err(|err| {
                InternalError::trace(
                    source!(),
                    StatusCode::BAD_REQUEST,
                    "Invalid private seed value",
                    err,
                )
            })?,
        })
    }
}

#[derive(Clone, Deserialize)]
pub struct PrivateKeySeed {
    pub first: [u8; 32],
    pub second: [u8; 32],
}

impl PrivateKeySeed {
    pub fn derive_key_pair(&self) -> InternalResult<(DerivedPublicKey, DerivedPrivateKey)> {
        let mut seed = [0u8; 32];

        Argon2::default()
            .hash_password_into(&self.first, &self.second, &mut seed)
            .map_err(|err| {
                InternalError::trace(
                    source!(),
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Internal error hashing private key",
                    err,
                )
            })?;

        let private_key = DerivedPrivateKey::from(seed);
        let public_key = DerivedPublicKey::from(&private_key);

        Ok((public_key, private_key))
    }

    pub async fn generate_access_key(project_id: Uuid) -> (String, Self) {
        let mut first = [0u8; 32];
        fill_random_bytes(&mut first).await;

        let mut second = [0u8; 32];
        fill_random_bytes(&mut second).await;

        let access_key = DirectAccessKey {
            project_id,
            first,
            second,
        };

        let seed = Self { first, second };
        (access_key.encode(), seed)
    }

    pub fn from_access_key(encoded: String) -> InternalResult<(Uuid, Self)> {
        let access_key: DirectAccessKey = DirectAccessKey::decode(&encoded)?;
        let seed = Self {
            first: access_key.first,
            second: access_key.second,
        };

        Ok((access_key.project_id, seed))
    }
}
