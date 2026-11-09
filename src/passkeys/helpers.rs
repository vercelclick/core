use crate::constants::{RP_ID, RP_ORIGIN};
use crate::passkeys::flags::PasskeyFlags;
use crate::result::{InternalError, InternalResult};
use crate::source;
use crate::utils::{bin_decode, bin_encode, sha256_digest};
use http::StatusCode;
use serde::Deserialize;
use sha2::{Digest, Sha256};

const CHALLENGE_LEN: usize = 32;

#[derive(Deserialize)]
struct ClientData {
    challenge: String,
    origin: String,
    #[serde(rename = "type")]
    type_: String,
}

impl ClientData {
    fn challenge(&self) -> InternalResult<Vec<u8>> {
        let challenge_bytes = bin_decode(&self.challenge)?;
        if challenge_bytes.len() != CHALLENGE_LEN {
            return Err(InternalError::new(
                source!(),
                StatusCode::CONFLICT,
                "Invalid challenge value",
            ));
        }
        Ok(challenge_bytes)
    }
}

pub fn verify_client_data(
    bytes: &[u8],
    expected_challenge_hash: &str,
    expected_type: &str,
) -> InternalResult<()> {
    let data: ClientData = serde_json::from_slice(bytes).map_err(|err| {
        InternalError::trace(
            source!(),
            StatusCode::CONFLICT,
            "Invalid client data content",
            err,
        )
    })?;
    let challenge = data.challenge()?;
    let challenge_hash = sha256_digest(&[bin_encode(&challenge)]);

    if challenge_hash != expected_challenge_hash {
        return Err(InternalError::new(
            source!(),
            StatusCode::CONFLICT,
            "Challenge value mismatch",
        ));
    }

    // Due to dynamic port configuration
    if data.origin != RP_ORIGIN {
        return Err(InternalError::new(
            source!(),
            StatusCode::CONFLICT,
            &format!(
                "Origin mismatch, expected: {}, got: {}",
                RP_ORIGIN, data.origin
            ),
        ));
    }

    if data.type_ != expected_type {
        return Err(InternalError::new(
            source!(),
            StatusCode::CONFLICT,
            &format!("Invalid operation type: {}", data.type_),
        ));
    }
    Ok(())
}

pub fn parse_auth_data(raw: &[u8]) -> InternalResult<(PasskeyFlags, Option<Vec<u8>>)> {
    if raw.len() < 37 {
        return Err(InternalError::new(
            source!(),
            StatusCode::CONFLICT,
            "Invalid auth data",
        ));
    }
    let rp_id_hash = raw[0..32].to_vec();

    verify_rp_id_hash(&rp_id_hash)?;

    let flags = PasskeyFlags::parse(raw[32]);

    let credential_data = if flags.attested_data {
        Some(raw[37..].to_vec())
    } else {
        None
    };

    Ok((flags, credential_data))
}

fn verify_rp_id_hash(hash: &[u8]) -> InternalResult<()> {
    let expected = Sha256::digest(RP_ID.as_bytes());
    if hash != expected.as_ref() as &[u8] {
        return Err(InternalError::new(
            source!(),
            StatusCode::CONFLICT,
            "RP ID mismatch",
        ));
    }
    Ok(())
}
