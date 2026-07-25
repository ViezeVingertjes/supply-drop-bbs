//! Flood scopes, called regions in the firmware.
//!
//! A mesh can require that flooded packets carry a transport code derived from
//! a shared scope key. Repeaters configured that way drop any packet whose
//! code they cannot reproduce, which keeps traffic inside one region.
//!
//! A scope named `nl` keys as `SHA256("#nl")` truncated to sixteen bytes,
//! matching `RegionMap::getTransportKeysFor` for an implicit hashtag region
//! (`RegionMap.cpp:180-184`) and the build-time default scope in
//! `companion_radio/MyMesh.cpp:928`. A name that already starts with `#` is
//! used as it stands.
//!
//! The code itself is `HMAC-SHA256(key, payload_type ‖ payload)` truncated to
//! two little-endian bytes, with `0x0000` and `0xFFFF` reserved
//! (`TransportKeyStore.cpp:4-18`).
//!
//! The modem exposes SHA-256 but no HMAC, so the HMAC construction is assembled
//! here from two device hashes. Only padding and exclusive-or happen on the
//! host; the compression function stays on the device.

use tokio::io::{AsyncRead, AsyncWrite};

use crate::error::KissError;
use crate::hw::client::HwLink;
use crate::hw::frame::{HwRequest, HwResponse};
use crate::packet::PayloadType;

/// Block size of SHA-256, which sets the HMAC key padding.
const HMAC_BLOCK: usize = 64;

/// Inner padding byte of the HMAC construction.
const IPAD: u8 = 0x36;

/// Outer padding byte of the HMAC construction.
const OPAD: u8 = 0x5C;

/// Length of a transport key.
pub const SCOPE_KEY_LEN: usize = 16;

/// A flood scope key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FloodScope {
    key: [u8; SCOPE_KEY_LEN],
}

impl FloodScope {
    /// Use a key that was derived elsewhere.
    #[must_use]
    pub fn from_key(key: [u8; SCOPE_KEY_LEN]) -> Self {
        Self { key }
    }

    /// The raw key bytes.
    #[must_use]
    pub fn key(&self) -> [u8; SCOPE_KEY_LEN] {
        self.key
    }

    /// Derive the key for a named scope, hashing on the device.
    ///
    /// The name is prefixed with `#` when it does not already carry one.
    ///
    /// # Errors
    ///
    /// Returns an error when the modem does not answer the hash request.
    pub async fn derive<S>(link: &mut HwLink<S>, name: &str) -> Result<Self, KissError>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send,
    {
        let hashtag = if name.starts_with('#') {
            name.to_owned()
        } else {
            format!("#{name}")
        };
        let digest = sha256(link, hashtag.as_bytes()).await?;
        let mut key = [0u8; SCOPE_KEY_LEN];
        key.copy_from_slice(&digest[..SCOPE_KEY_LEN]);
        Ok(Self { key })
    }

    /// Compute the transport code for a packet's payload.
    ///
    /// # Errors
    ///
    /// Returns an error when the modem does not answer a hash request.
    pub async fn transport_code<S>(
        &self,
        link: &mut HwLink<S>,
        payload_type: PayloadType,
        payload: &[u8],
    ) -> Result<u16, KissError>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send,
    {
        let mut message = Vec::with_capacity(1 + payload.len());
        message.push(payload_type as u8);
        message.extend_from_slice(payload);

        let mac = self.hmac(link, &message).await?;
        let code = u16::from_le_bytes([mac[0], mac[1]]);
        Ok(match code {
            0x0000 => 0x0001,
            0xFFFF => 0xFFFE,
            other => other,
        })
    }

    async fn hmac<S>(&self, link: &mut HwLink<S>, message: &[u8]) -> Result<[u8; 32], KissError>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send,
    {
        let mut padded = [0u8; HMAC_BLOCK];
        padded[..SCOPE_KEY_LEN].copy_from_slice(&self.key);

        let mut inner = Vec::with_capacity(HMAC_BLOCK + message.len());
        inner.extend(padded.iter().map(|byte| byte ^ IPAD));
        inner.extend_from_slice(message);
        let inner_digest = sha256(link, &inner).await?;

        let mut outer = Vec::with_capacity(HMAC_BLOCK + inner_digest.len());
        outer.extend(padded.iter().map(|byte| byte ^ OPAD));
        outer.extend_from_slice(&inner_digest);
        sha256(link, &outer).await
    }
}

async fn sha256<S>(link: &mut HwLink<S>, data: &[u8]) -> Result<[u8; 32], KissError>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    match link
        .request(HwRequest::Hash {
            data: data.to_vec(),
        })
        .await?
    {
        HwResponse::Hash { digest } => Ok(digest),
        other => Err(KissError::malformed(format!(
            "expected a digest, got {other:?}"
        ))),
    }
}
