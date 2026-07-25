//! Acknowledgement hashes for direct text messages.
//!
//! The MeshCore firmware proves receipt by hashing the message plaintext
//! together with a public key and truncating the digest to four bytes. The
//! digest itself comes from the modem's `Hash` sub-command, so no hashing
//! happens here. This module owns which bytes go into the hash, how the
//! resulting digest is read back, and the pending table that correlates a
//! message we sent with the acknowledgement that confirms it.
//!
//! # Hashed input
//!
//! The firmware hashes two fragments in sequence through
//! `Utils::sha256(hash, hash_len, frag1, frag1_len, frag2, frag2_len)`
//! (`MeshCore/src/Utils.cpp:23`), which feeds `frag1` then `frag2` into one
//! SHA-256 context. That is the same digest as hashing the two fragments
//! concatenated, so a single `Hash` request covers both.
//!
//! ```text
//! byte    0   1   2   3   4   5                  5 + text_len
//!       +---------------+---+------------------+------------------+
//!       | timestamp LE  | f | text             | public key       |
//!       +---------------+---+------------------+------------------+
//!         4 bytes         1   text_len bytes     32 bytes
//! ```
//!
//! `f` packs the message type into the high six bits and the attempt number
//! into the low two, as [`TxtMsgPlain::encode`] writes it. The text is hashed
//! without its NUL terminator and without the zero padding the block cipher
//! adds, because the firmware passes `5 + text_len` as the fragment length,
//! where `text_len` is `strlen` of the text.
//!
//! # The public key differs by direction
//!
//! Whoever receives a message hashes it against the public key of whoever sent
//! it. That one rule reads two ways depending on which side you stand on, and
//! getting it backwards makes every reply look undelivered:
//!
//! - **Outbound**, deriving the acknowledgement we expect back for a message we
//!   sent, hashes against **our own** public key. The recipient will hash
//!   against the key of the sender, and for our own messages we are the sender.
//!   `MeshCore/src/helpers/BaseChatMesh.cpp:431` passes `self_id.pub_key`.
//! - **Inbound**, deriving the acknowledgement we send for a message we
//!   received, hashes against the **sender's** public key.
//!   `MeshCore/src/helpers/BaseChatMesh.cpp:243` passes `from.id.pub_key`.
//!
//! [`ack_hash_input`] takes the key as an argument and cannot tell the two
//! directions apart. The caller picks the key.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use crate::packet::TxtMsgPlain;

/// Build the byte sequence whose SHA-256 digest is the acknowledgement hash.
///
/// Returns `plain.ack_input_bytes()` followed by `pubkey`, which is
/// `4 + 1 + text.len() + 32` bytes. Pass the result to the modem's `Hash`
/// sub-command.
///
/// `pubkey` is our own public key when deriving the acknowledgement we expect
/// back for a message we sent, and the sender's public key when deriving the
/// acknowledgement we send for a message we received. See the module
/// documentation.
#[must_use]
pub fn ack_hash_input(plain: &TxtMsgPlain, pubkey: &[u8; 32]) -> Vec<u8> {
    let mut input = plain.ack_input_bytes();
    input.extend_from_slice(pubkey);
    input
}

/// Read the acknowledgement CRC out of a digest.
///
/// The firmware truncates the digest to four bytes and reads them as a native
/// `uint32_t` on a little-endian MCU, so the CRC is
/// `u32::from_le_bytes(digest[0..4])`. `bbs-mesh` compares this value against
/// the `crc` of `InboundFrame::SendConfirmed`, which `meshcore-companion`
/// decodes with `u32::from_le_bytes` as well, so both backends agree.
#[must_use]
pub fn expected_ack_from_digest(digest: &[u8; 32]) -> u32 {
    u32::from_le_bytes([digest[0], digest[1], digest[2], digest[3]])
}

/// Build the six-byte acknowledgement body sent for a message we received.
///
/// The first four bytes are the truncated digest. The fifth is the extended
/// attempt byte and the sixth is random, which together keep the packet hash
/// unique across retransmissions of the same text.
///
/// `extended_attempt` is the byte the sender appended at offset
/// `5 + text_len + 1` of the plaintext, one past the NUL terminator. A sender
/// writes it only for attempt numbers above three
/// (`MeshCore/src/helpers/BaseChatMesh.cpp:437`), so it is zero for ordinary
/// messages. It is not the two-bit attempt field packed into the flags byte.
///
/// `random_byte` comes from the modem's random-number sub-command.
#[must_use]
pub fn inbound_ack_hash(digest: &[u8; 32], extended_attempt: u8, random_byte: u8) -> [u8; 6] {
    [
        digest[0],
        digest[1],
        digest[2],
        digest[3],
        extended_attempt,
        random_byte,
    ]
}

/// A value awaiting its acknowledgement, with the time it was recorded.
#[derive(Debug)]
struct Pending<T> {
    value: T,
    since: Instant,
}

/// Messages sent and not yet acknowledged, keyed by their expected CRC.
///
/// `T` is whatever the caller needs back when the acknowledgement arrives, such
/// as a queued message and its retry state. Nothing in this table interprets
/// `T`.
///
/// A CRC is four bytes of a hash, so two different messages can collide under
/// one key. The firmware accepts that risk and so does this table:
/// [`PendingAcks::insert`] replaces any entry already stored under the key.
#[derive(Debug)]
pub struct PendingAcks<T> {
    entries: HashMap<u32, Pending<T>>,
}

impl<T> Default for PendingAcks<T> {
    fn default() -> Self {
        Self {
            entries: HashMap::new(),
        }
    }
}

impl<T> PendingAcks<T> {
    /// Create an empty table.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Record `value` under the CRC its acknowledgement will carry.
    ///
    /// The entry is stamped with the current time for [`PendingAcks::expire`].
    /// An existing entry under the same CRC is replaced.
    pub fn insert(&mut self, crc: u32, value: T) {
        self.entries.insert(
            crc,
            Pending {
                value,
                since: Instant::now(),
            },
        );
    }

    /// Remove and return the entry matching `crc`, if there is one.
    pub fn take(&mut self, crc: u32) -> Option<T> {
        self.entries.remove(&crc).map(|pending| pending.value)
    }

    /// How many entries are waiting.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether no entry is waiting.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Remove and return every entry recorded more than `ttl` before `now`.
    ///
    /// The caller decides what an expiry means. A retry layer resends the
    /// returned messages, a metrics layer counts them as lost.
    ///
    /// The order of the returned entries is unspecified.
    pub fn expire(&mut self, now: Instant, ttl: Duration) -> Vec<T> {
        let stale: Vec<u32> = self
            .entries
            .iter()
            .filter(|(_, pending)| now.saturating_duration_since(pending.since) > ttl)
            .map(|(crc, _)| *crc)
            .collect();

        stale
            .into_iter()
            .filter_map(|crc| self.entries.remove(&crc))
            .map(|pending| pending.value)
            .collect()
    }
}
