use crate::passkeys::flags::PasskeyFlags;
use crate::utils::{bin_decode, bin_encode, sha256_digest};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use wasm_bindgen::throw_str;

const CHALLENGE_LEN: usize = 32;

#[derive(Deserialize)]
struct ClientData {
    challenge: String,
    origin: String,
    #[serde(rename = "type")]
    type_: String,
}

impl ClientData {
    fn challenge(&self) -> anyhow::Result<Vec<u8>> {
        let challenge_bytes = bin_decode(&self.challenge)?;
        if challenge_bytes.len() != CHALLENGE_LEN {
            throw_str("Invalid challenge length")
        }
        Ok(challenge_bytes)
    }
}

pub fn verify_client_data(
    bytes: &[u8],
    expected_challenge_hash: &str,
    expected_type: &str,
    expected_origin: &str,
) -> anyhow::Result<()> {
    let data: ClientData = serde_json::from_slice(bytes)?;
    let challenge = data.challenge()?;
    let challenge_hash = sha256_digest(&[bin_encode(&challenge)]);

    if challenge_hash != expected_challenge_hash {
        return Err(anyhow::anyhow!("Invalid challenge"));
    }

    // Due to dynamic port configuration
    if data.origin != expected_origin {
        return Err(anyhow::format_err!(
            "Origin mismatch, expected: {}, got: {}",
            expected_origin,
            data.origin
        ));
    }

    if data.type_ != expected_type {
        return Err(anyhow::format_err!(
            "Invalid operation type: {}",
            data.type_
        ));
    }
    Ok(())
}

pub fn parse_auth_data(
    raw: &[u8],
    expected_rp_id: &str,
) -> anyhow::Result<(PasskeyFlags, Option<Vec<u8>>)> {
    if raw.len() < 37 {
        return Err(anyhow::anyhow!("authData too short"));
    }
    let rp_id_hash = raw[0..32].to_vec();

    verify_rp_id_hash(&rp_id_hash, expected_rp_id)?;

    let flags = PasskeyFlags::parse(raw[32]);

    let credential_data = if flags.attested_data {
        Some(raw[37..].to_vec())
    } else {
        None
    };

    Ok((flags, credential_data))
}

fn verify_rp_id_hash(hash: &[u8], expected_rp_id: &str) -> anyhow::Result<()> {
    let expected = Sha256::digest(expected_rp_id.as_bytes());
    if hash != expected.as_ref() as &[u8] {
        return Err(anyhow::anyhow!("RP ID hash mismatch"));
    }
    Ok(())
}
