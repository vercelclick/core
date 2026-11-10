use crate::result::{InternalError, InternalResult};

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use http::StatusCode;
use rand::rngs::{ChaCha20Rng, SysRng};
use rand::{RngExt, SeedableRng, TryRng};
use serde::Serialize;
use serde::de::DeserializeOwned;
use sha2::{Digest, Sha256};

use std::io::Cursor;
use std::sync::{Mutex, OnceLock};

static RNG: OnceLock<Mutex<ChaCha20Rng>> = OnceLock::new();

pub fn get_global_rng() -> &'static Mutex<ChaCha20Rng> {
    RNG.get_or_init(|| {
        let mut seed = [0u8; 32];
        SysRng.try_fill_bytes(&mut seed).unwrap();
        Mutex::new(ChaCha20Rng::from_seed(seed))
    })
}

pub fn fill_random_bytes(bytes: &mut [u8]) {
    let mut rng = get_global_rng().lock().unwrap();
    rng.fill(bytes);
}

pub fn sha256_raw(items: &[String]) -> [u8; 32] {
    let mut hash = Sha256::new();
    for value in items {
        hash.update(value.as_bytes());
    }

    let result = hash.finalize();

    let output: [u8; 32] = result.as_slice().try_into().unwrap();
    output
}

pub fn sha256_digest(items: &[String]) -> String {
    hex::encode(sha256_raw(items))
}

pub fn bin_encode(payload: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(payload)
}

pub fn bin_decode(payload: &str) -> InternalResult<Vec<u8>> {
    URL_SAFE_NO_PAD.decode(payload).map_err(|err| {
        InternalError::trace(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Base64 content decode error",
            err,
        )
    })
}

pub fn bin_serialize<T>(payload: &T) -> InternalResult<String>
where
    T: Serialize,
{
    let mut serialized = Vec::new();
    ciborium::ser::into_writer(payload, &mut serialized).map_err(|err| {
        InternalError::trace(StatusCode::CONFLICT, "Binary content encode error", err)
    })?;

    Ok(bin_encode(&serialized))
}

pub fn bin_deserialize<T>(payload: &str) -> InternalResult<T>
where
    T: DeserializeOwned,
{
    let decoded = bin_decode(payload)?;

    let mut reader = Cursor::new(&decoded);
    let result: T = ciborium::de::from_reader(&mut reader).map_err(|err| {
        InternalError::trace(StatusCode::CONFLICT, "Binary content decode error", err)
    })?;

    Ok(result)
}
