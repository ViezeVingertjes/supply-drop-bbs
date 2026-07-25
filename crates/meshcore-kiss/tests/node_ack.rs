//! Acknowledgement hash derivation and the pending-acknowledgement table.
//!
//! The byte layout under test comes from `MeshCore/src/helpers/BaseChatMesh.cpp`
//! at line 243 for the inbound direction and line 431 for the outbound one. A
//! single wrong byte here makes every reply look undelivered, so the vectors
//! are written out literally rather than derived from the implementation.

use std::time::{Duration, Instant};

use meshcore_kiss::node::ack::{
    ack_hash_input, expected_ack_from_digest, inbound_ack_hash, PendingAcks,
};
use meshcore_kiss::packet::TxtMsgPlain;

fn digest_of(first_four: [u8; 4]) -> [u8; 32] {
    let mut digest = [0u8; 32];
    digest[..4].copy_from_slice(&first_four);
    digest
}

#[test]
fn ack_hash_input_is_plaintext_then_pubkey() {
    let plain = TxtMsgPlain {
        timestamp: 1_700_000_000,
        txt_type: 0,
        attempt: 0,
        text: "hello".into(),
        extended_attempt: 0,
    };
    let pubkey = [0x33u8; 32];
    let input = ack_hash_input(&plain, &pubkey);

    let encoded = plain.encode();
    assert_eq!(input.len(), encoded.len() + 32);
    assert_eq!(&input[..encoded.len()], &encoded[..]);
    assert_eq!(&input[encoded.len()..], &pubkey[..]);
}

#[test]
fn ack_hash_input_excludes_block_cipher_padding() {
    let plain = TxtMsgPlain {
        timestamp: 7,
        txt_type: 0,
        attempt: 0,
        text: "hi".into(),
        extended_attempt: 0,
    };
    let input = ack_hash_input(&plain, &[0x01; 32]);
    assert_eq!(input.len(), 4 + 1 + 2 + 32);
}

#[test]
fn expected_ack_reads_first_four_digest_bytes_little_endian() {
    let digest = [
        0x78, 0x56, 0x34, 0x12, 0xFF, 0xFF, 0xFF, 0xFF, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    ];
    assert_eq!(expected_ack_from_digest(&digest), 0x1234_5678);
}

#[test]
fn pending_acks_matches_and_removes_by_crc() {
    let mut pending = PendingAcks::default();
    pending.insert(0xDEAD_BEEF, 42);
    assert_eq!(pending.take(0x0000_0001), None);
    assert_eq!(pending.take(0xDEAD_BEEF), Some(42));
    assert_eq!(pending.take(0xDEAD_BEEF), None);
}

#[test]
fn ack_hash_input_length_is_timestamp_flags_text_and_pubkey() {
    for text in ["", "a", "the quick brown fox", "ünïcödé ✓ 日本語"] {
        let plain = TxtMsgPlain {
            timestamp: 0x0102_0304,
            txt_type: 0,
            attempt: 0,
            text: text.into(),
            extended_attempt: 0,
        };
        let input = ack_hash_input(&plain, &[0x5Au8; 32]);
        assert_eq!(
            input.len(),
            4 + 1 + text.len() + 32,
            "wrong length for {text:?}"
        );
    }
}

#[test]
fn ack_hash_input_starts_with_little_endian_timestamp_and_packed_flags() {
    let plain = TxtMsgPlain {
        timestamp: 0x1122_3344,
        txt_type: 0,
        attempt: 2,
        text: "ok".into(),
        extended_attempt: 0,
    };
    let input = ack_hash_input(&plain, &[0u8; 32]);
    assert_eq!(&input[..4], &[0x44, 0x33, 0x22, 0x11]);
    assert_eq!(input[4], 0x02);
    assert_eq!(&input[5..7], b"ok");
}

#[test]
fn ack_hash_input_tail_is_the_key_it_was_given() {
    let plain = TxtMsgPlain {
        timestamp: 1_700_000_000,
        txt_type: 0,
        attempt: 0,
        text: "ack vector".into(),
        extended_attempt: 0,
    };
    let ours = [0x11u8; 32];
    let theirs = [0x22u8; 32];

    let outbound = ack_hash_input(&plain, &ours);
    let inbound = ack_hash_input(&plain, &theirs);

    assert_ne!(
        outbound, inbound,
        "the pubkey must change the hashed input, otherwise a swapped direction is undetectable"
    );
    assert_eq!(&outbound[outbound.len() - 32..], &ours[..]);
    assert_eq!(&inbound[inbound.len() - 32..], &theirs[..]);
    assert_eq!(
        &outbound[..outbound.len() - 32],
        &inbound[..inbound.len() - 32]
    );
}

#[test]
fn inbound_ack_hash_is_four_digest_bytes_then_attempt_then_random() {
    let digest = digest_of([0xAA, 0xBB, 0xCC, 0xDD]);
    let hash = inbound_ack_hash(&digest, 0x05, 0x9E);
    assert_eq!(hash, [0xAA, 0xBB, 0xCC, 0xDD, 0x05, 0x9E]);
}

#[test]
fn inbound_ack_hash_shares_its_first_four_bytes_with_the_expected_crc() {
    let digest = digest_of([0x78, 0x56, 0x34, 0x12]);
    let hash = inbound_ack_hash(&digest, 0, 0);
    assert_eq!(
        u32::from_le_bytes([hash[0], hash[1], hash[2], hash[3]]),
        expected_ack_from_digest(&digest)
    );
}

#[test]
fn expected_ack_ignores_everything_past_the_fourth_digest_byte() {
    let mut digest = digest_of([1, 2, 3, 4]);
    for byte in digest.iter_mut().skip(4) {
        *byte = 0x5A;
    }
    let crc = expected_ack_from_digest(&digest);

    for byte in digest.iter_mut().skip(4) {
        *byte = 0xA5;
    }
    assert_eq!(expected_ack_from_digest(&digest), crc);
    assert_eq!(crc, 0x0403_0201);
}

#[test]
fn pending_acks_reports_length_and_emptiness() {
    let mut pending = PendingAcks::default();
    assert!(pending.is_empty());
    assert_eq!(pending.len(), 0);

    pending.insert(1, "one");
    pending.insert(2, "two");
    assert!(!pending.is_empty());
    assert_eq!(pending.len(), 2);

    assert_eq!(pending.take(1), Some("one"));
    assert_eq!(pending.len(), 1);
}

#[test]
fn pending_acks_expire_returns_and_drops_only_stale_entries() {
    let mut pending = PendingAcks::default();
    pending.insert(0xAAAA_AAAA, "stale");
    let future = Instant::now() + Duration::from_secs(600);

    let expired = pending.expire(future, Duration::from_secs(60));
    assert_eq!(expired, vec!["stale"]);
    assert!(pending.is_empty());
    assert_eq!(pending.take(0xAAAA_AAAA), None);
}

#[test]
fn pending_acks_expire_keeps_fresh_entries() {
    let mut pending = PendingAcks::default();
    pending.insert(0xBBBB_BBBB, "fresh");

    let expired = pending.expire(Instant::now(), Duration::from_secs(600));
    assert!(expired.is_empty());
    assert_eq!(pending.len(), 1);
    assert_eq!(pending.take(0xBBBB_BBBB), Some("fresh"));
}

#[test]
fn pending_acks_expire_on_an_empty_table_returns_nothing() {
    let mut pending: PendingAcks<u8> = PendingAcks::default();
    assert!(pending
        .expire(Instant::now(), Duration::from_secs(1))
        .is_empty());
}

#[test]
fn pending_acks_holds_a_value_that_does_not_implement_default() {
    /// A stand-in for the queued-message type a later task will store.
    struct Queued {
        /// The CRC the acknowledgement for this message will carry.
        crc: u32,
    }

    let mut pending = PendingAcks::default();
    pending.insert(0xC0FF_EE00, Queued { crc: 0xC0FF_EE00 });
    let taken = pending.take(0xC0FF_EE00).expect("entry is present");
    assert_eq!(taken.crc, 0xC0FF_EE00);
}
