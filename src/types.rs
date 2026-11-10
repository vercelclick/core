use crate::result::{InternalError, InternalResult};

use crate::utils::{bin_decode, bin_encode};
use http::StatusCode;

// No keys for smaller payloads
pub struct EncryptedPackage {
    /// Derived ECC public key bytes
    pub public_key: [u8; 32],
    /// Nonce Bytes
    pub nonce_bytes: [u8; 12],
    pub ciphertext: Vec<u8>,
}

impl EncryptedPackage {
    pub fn encode_binary(&self) -> Vec<u8> {
        let group = [
            &self.public_key[..],
            &self.nonce_bytes[..],
            &self.ciphertext[..],
        ];
        group.concat()
    }

    pub fn encode(&self) -> String {
        bin_encode(&self.encode_binary())
    }

    pub fn decode(payload: &str) -> InternalResult<Self> {
        let binary_payload = bin_decode(payload)?;
        Self::decode_binary(&binary_payload)
    }

    pub fn decode_binary(raw_payload: &[u8]) -> InternalResult<Self> {
        let public_key = &raw_payload[..32];
        let nonce_bytes = &raw_payload[32..44];
        let payload = &raw_payload[44..];

        Ok(Self {
            public_key: public_key.try_into().map_err(|err| {
                InternalError::trace(
                    StatusCode::CONFLICT,
                    "Invalid encrypted package public key value",
                    err,
                )
            })?,
            nonce_bytes: nonce_bytes.try_into().map_err(|err| {
                InternalError::trace(
                    StatusCode::CONFLICT,
                    "Invalid encrypted package nonce value",
                    err,
                )
            })?,
            ciphertext: payload.to_vec(),
        })
    }
}
