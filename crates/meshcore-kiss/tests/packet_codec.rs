#![allow(missing_docs)]

use meshcore_kiss::packet::{
    pack_path_length, path_byte_len, path_hash_count, path_hash_size, AdvertBody, EncryptedBody,
    Packet, PathBody, PayloadType, RouteType, TxtMsgPlain, MAX_PATH_SIZE,
};
use proptest::prelude::*;

#[test]
fn header_splits_into_route_payload_and_version() {
    let header = 0b0001_0001u8;
    let packet = Packet::decode(&[header, 0x00, 0xAA]).expect("decodes");
    assert_eq!(packet.route_type(), RouteType::Flood);
    assert_eq!(packet.payload_type(), PayloadType::Advert);
    assert_eq!(packet.payload_version(), 0);
    assert_eq!(packet.payload, vec![0xAA]);
}

#[test]
fn path_length_encodes_hash_size_and_hop_count() {
    let mut raw = vec![0b0000_1010u8, 0x45];
    raw.extend_from_slice(&[0x11; 10]);
    raw.push(0xFF);
    let packet = Packet::decode(&raw).expect("decodes");
    assert_eq!(packet.path_hash_size(), 2);
    assert_eq!(packet.path_hash_count(), 5);
    assert_eq!(packet.path, vec![0x11; 10]);
    assert_eq!(packet.payload, vec![0xFF]);
}

#[test]
fn zero_hop_packet_has_no_path_bytes() {
    let packet = Packet::decode(&[0b0000_1010u8, 0x00, 0x01, 0x02]).expect("decodes");
    assert_eq!(packet.path_hash_count(), 0);
    assert!(packet.path.is_empty());
    assert_eq!(packet.payload, vec![0x01, 0x02]);
}

#[test]
fn encode_roundtrips_decode() {
    let mut raw = vec![0b0000_1010u8, 0x83];
    raw.extend_from_slice(&[0x22; 9]);
    raw.extend_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]);
    let packet = Packet::decode(&raw).expect("decodes");
    assert_eq!(packet.encode(), raw);
}

#[test]
fn transport_route_types_carry_four_extra_header_bytes() {
    let mut raw = vec![0b0001_0000u8];
    raw.extend_from_slice(&[0x01, 0x02, 0x03, 0x04]);
    raw.push(0x00);
    raw.push(0x99);
    let packet = Packet::decode(&raw).expect("decodes");
    assert_eq!(packet.route_type(), RouteType::TransportFlood);
    assert_eq!(packet.transport_codes, Some([0x0201, 0x0403]));
    assert_eq!(packet.payload, vec![0x99]);
}

#[test]
fn oversized_path_is_rejected() {
    let raw = vec![0b0000_1010u8, 0xBF];
    assert!(Packet::decode(&raw).is_err());
}

#[test]
fn oversized_payload_is_rejected() {
    let mut raw = vec![0b0000_1010u8, 0x00];
    raw.extend(std::iter::repeat_n(0xAA, 200));
    assert!(Packet::decode(&raw).is_err());
}

#[test]
fn advert_body_splits_key_timestamp_signature_and_appdata() {
    let mut body = Vec::new();
    body.extend_from_slice(&[0x01; 32]);
    body.extend_from_slice(&1_700_000_000u32.to_le_bytes());
    body.extend_from_slice(&[0x02; 64]);
    body.push(0x81);
    body.extend_from_slice(b"BBS");

    let advert = AdvertBody::parse(&body).expect("parses");
    assert_eq!(advert.pubkey, [0x01; 32]);
    assert_eq!(advert.timestamp, 1_700_000_000);
    assert_eq!(advert.signature, [0x02; 64]);
    assert_eq!(advert.flags, 0x81);
    assert_eq!(advert.name.as_deref(), Some("BBS"));
    assert_eq!(advert.latitude_1e6, None);
    assert_eq!(
        advert.signed_bytes(),
        body[..32 + 4]
            .iter()
            .copied()
            .chain(body[100..].iter().copied())
            .collect::<Vec<_>>()
    );
}

#[test]
fn advert_body_reads_location_when_flag_set() {
    let mut body = Vec::new();
    body.extend_from_slice(&[0x01; 32]);
    body.extend_from_slice(&0u32.to_le_bytes());
    body.extend_from_slice(&[0x02; 64]);
    body.push(0x91);
    body.extend_from_slice(&52_370_000i32.to_le_bytes());
    body.extend_from_slice(&4_890_000i32.to_le_bytes());
    body.extend_from_slice(b"Node");

    let advert = AdvertBody::parse(&body).expect("parses");
    assert_eq!(advert.latitude_1e6, Some(52_370_000));
    assert_eq!(advert.longitude_1e6, Some(4_890_000));
    assert_eq!(advert.name.as_deref(), Some("Node"));
}

#[test]
fn encrypted_body_splits_hashes_mac_and_ciphertext() {
    let body = vec![0xAA, 0xBB, 0x11, 0x22, 0x33, 0x44, 0x55];
    let parsed = EncryptedBody::parse(&body).expect("parses");
    assert_eq!(parsed.dest_hash, 0xAA);
    assert_eq!(parsed.src_hash, 0xBB);
    assert_eq!(parsed.mac, [0x11, 0x22]);
    assert_eq!(parsed.ciphertext, vec![0x33, 0x44, 0x55]);
}

#[test]
fn txt_msg_plaintext_packs_type_and_attempt_into_one_byte() {
    let plain = TxtMsgPlain {
        timestamp: 1_700_000_000,
        txt_type: 0,
        attempt: 2,
        text: "hello".into(),
        extended_attempt: 0,
    };
    let bytes = plain.encode();
    assert_eq!(&bytes[..4], &1_700_000_000u32.to_le_bytes());
    assert_eq!(bytes[4], 0b0000_0010);
    assert_eq!(&bytes[5..], b"hello");

    let parsed = TxtMsgPlain::parse(&bytes).expect("parses");
    assert_eq!(parsed, plain);
}

#[test]
fn txt_msg_plaintext_ignores_zero_padding_from_block_cipher() {
    let mut bytes = TxtMsgPlain {
        timestamp: 7,
        txt_type: 0,
        attempt: 0,
        text: "hi".into(),
        extended_attempt: 0,
    }
    .encode();
    bytes.extend_from_slice(&[0x00; 9]);
    let parsed = TxtMsgPlain::parse(&bytes).expect("parses");
    assert_eq!(parsed.text, "hi");
}

proptest! {
    #[test]
    fn packet_encode_decode_roundtrips(
        payload_type in 0u8..=11,
        hash_size in 1u8..=3,
        hop_count in 0u8..=20,
        payload in prop::collection::vec(any::<u8>(), 1..180),
    ) {
        let path_len = usize::from(hash_size) * usize::from(hop_count);
        prop_assume!(path_len <= 64);
        let header = (payload_type << 2) | 0x02;
        let mut raw = vec![header, ((hash_size - 1) << 6) | hop_count];
        raw.extend(std::iter::repeat_n(0x5A, path_len));
        raw.extend_from_slice(&payload);

        let packet = Packet::decode(&raw).expect("decodes");
        prop_assert_eq!(packet.path_hash_size(), hash_size);
        prop_assert_eq!(packet.path_hash_count(), hop_count);
        prop_assert_eq!(packet.encode(), raw);
    }
}

fn advert_bytes(appdata: &[u8]) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&[0x01; 32]);
    body.extend_from_slice(&1_700_000_000u32.to_le_bytes());
    body.extend_from_slice(&[0x02; 64]);
    body.extend_from_slice(appdata);
    body
}

#[test]
fn signed_bytes_preserves_reserved_feature_fields() {
    let mut appdata = vec![0xA1];
    appdata.extend_from_slice(&[0xDE, 0xAD]);
    appdata.extend_from_slice(b"Node");
    let body = advert_bytes(&appdata);

    let advert = AdvertBody::parse(&body).expect("parses");
    assert_eq!(advert.name.as_deref(), Some("Node"));
    assert_eq!(advert.appdata, appdata);
    assert_eq!(&advert.signed_bytes()[36..], &appdata[..]);
}

#[test]
fn signed_bytes_preserves_a_name_that_is_not_valid_utf8() {
    let mut appdata = vec![0x81];
    appdata.extend_from_slice(&[0x4E, 0xFF, 0xFE, 0x64]);
    let body = advert_bytes(&appdata);

    let advert = AdvertBody::parse(&body).expect("parses");
    assert_eq!(advert.appdata, appdata);
    assert_eq!(&advert.signed_bytes()[36..], &appdata[..]);
}

#[test]
fn signed_bytes_matches_the_received_payload_byte_for_byte() {
    let mut appdata = vec![0x91];
    appdata.extend_from_slice(&52_370_000i32.to_le_bytes());
    appdata.extend_from_slice(&4_890_000i32.to_le_bytes());
    appdata.extend_from_slice(b"Peer");
    let body = advert_bytes(&appdata);

    let advert = AdvertBody::parse(&body).expect("parses");
    let mut expected = body[..36].to_vec();
    expected.extend_from_slice(&body[100..]);
    assert_eq!(advert.signed_bytes(), expected);
    assert_eq!(advert.encode(), body);
}

#[test]
fn unsigned_advert_composes_appdata_that_signed_bytes_reproduces() {
    let advert = AdvertBody::unsigned([0x07; 32], 42, 0x01, None, Some("Supply Drop"));
    assert_eq!(advert.flags, 0x81);
    assert_eq!(advert.appdata[0], 0x81);
    assert_eq!(&advert.appdata[1..], b"Supply Drop");

    let reparsed = AdvertBody::parse(&advert.encode()).expect("parses");
    assert_eq!(reparsed.appdata, advert.appdata);
    assert_eq!(reparsed.signed_bytes(), advert.signed_bytes());
}

#[test]
fn unsigned_advert_sets_the_location_flag_and_orders_lat_before_lon() {
    let advert = AdvertBody::unsigned(
        [0x07; 32],
        42,
        0x01,
        Some((52_370_000, 4_890_000)),
        Some("N"),
    );
    assert_eq!(advert.flags, 0x91);
    assert_eq!(&advert.appdata[1..5], &52_370_000i32.to_le_bytes());
    assert_eq!(&advert.appdata[5..9], &4_890_000i32.to_le_bytes());

    let reparsed = AdvertBody::parse(&advert.encode()).expect("parses");
    assert_eq!(reparsed.latitude_1e6, Some(52_370_000));
    assert_eq!(reparsed.longitude_1e6, Some(4_890_000));
    assert_eq!(reparsed.name.as_deref(), Some("N"));
}

#[test]
fn text_ends_at_the_first_nul_not_the_last_non_zero_byte() {
    let mut wire = Vec::new();
    wire.extend_from_slice(&7u32.to_le_bytes());
    wire.push(0b0000_0001);
    wire.extend_from_slice(b"hi");
    wire.push(0x00);
    wire.push(0x05);
    wire.extend_from_slice(&[0x00; 9]);

    let parsed = TxtMsgPlain::parse(&wire).expect("parses");
    assert_eq!(parsed.text, "hi");
    assert_eq!(parsed.attempt, 1);
    assert_eq!(parsed.extended_attempt, 5);
}

#[test]
fn ack_input_bytes_stop_before_the_terminator_and_extended_attempt() {
    let plain = TxtMsgPlain {
        timestamp: 7,
        txt_type: 0,
        attempt: 1,
        text: "hi".into(),
        extended_attempt: 5,
    };
    let ack_input = plain.ack_input_bytes();
    assert_eq!(ack_input.len(), 4 + 1 + 2);
    assert_eq!(&ack_input[5..], b"hi");

    let wire = plain.encode();
    assert_eq!(wire.len(), 4 + 1 + 2 + 2);
    assert_eq!(&wire[7..], &[0x00, 0x05]);
}

#[test]
fn attempts_up_to_three_carry_no_tail_bytes() {
    let plain = TxtMsgPlain {
        timestamp: 7,
        txt_type: 0,
        attempt: 3,
        text: "hi".into(),
        extended_attempt: 0,
    };
    assert_eq!(plain.encode(), plain.ack_input_bytes());

    let parsed = TxtMsgPlain::parse(&plain.encode()).expect("parses");
    assert_eq!(parsed.text, "hi");
    assert_eq!(parsed.extended_attempt, 0);
}

#[test]
fn extended_attempt_survives_an_encode_parse_roundtrip() {
    let plain = TxtMsgPlain {
        timestamp: 1_700_000_000,
        txt_type: 0,
        attempt: 1,
        text: "retry me".into(),
        extended_attempt: 5,
    };
    let parsed = TxtMsgPlain::parse(&plain.encode()).expect("parses");
    assert_eq!(parsed, plain);
}

// ─── path_length, the packed byte ──────────────────────────────────
//
// `path_length` is not a byte count. These tests pin the encoding against
// byte vectors shaped the way the firmware writes them, because a round trip
// through this crate's own encoder agrees with itself whether or not it agrees
// with MeshCore.

#[test]
fn path_length_packs_hash_width_above_hop_count() {
    assert_eq!(pack_path_length(1, 0), 0x00);
    assert_eq!(pack_path_length(1, 5), 0x05);
    assert_eq!(pack_path_length(2, 5), 0x45);
    assert_eq!(pack_path_length(3, 1), 0x81);
    assert_eq!(pack_path_length(3, 63), 0xBF);
}

#[test]
fn path_byte_len_multiplies_hops_by_hash_width() {
    assert_eq!(path_byte_len(pack_path_length(1, 6)), Some(6));
    assert_eq!(path_byte_len(pack_path_length(2, 3)), Some(6));
    assert_eq!(path_byte_len(pack_path_length(3, 2)), Some(6));
    assert_eq!(path_byte_len(0x00), Some(0));
}

#[test]
fn path_byte_len_refuses_the_reserved_width_and_oversized_paths() {
    assert_eq!(path_byte_len(0xC1), None, "reserved 4-byte hash size");
    assert_eq!(path_byte_len(0xFF), None, "reserved width, 63 hops");
    assert_eq!(
        path_byte_len(pack_path_length(3, 63)),
        None,
        "63 three-byte hops is 189 bytes, over MAX_PATH_SIZE"
    );
    assert_eq!(path_byte_len(pack_path_length(1, 63)), Some(63));
}

#[test]
fn pack_path_length_clamps_rather_than_wrapping() {
    assert_eq!(pack_path_length(0, 1), pack_path_length(1, 1));
    assert_eq!(pack_path_length(9, 1), pack_path_length(3, 1));
    assert_eq!(path_hash_count(pack_path_length(1, 64)), 0);
}

#[test]
fn build_reduces_the_hop_count_to_the_path_it_was_given() {
    let packet = Packet::build(
        RouteType::Direct,
        PayloadType::Ack,
        pack_path_length(3, 4),
        &[0x11; 6],
        vec![0xAA],
    );
    assert_eq!(packet.path_hash_size(), 3);
    assert_eq!(packet.path_hash_count(), 2, "only two whole hops supplied");
    assert_eq!(packet.path, vec![0x11; 6]);
    assert_eq!(Packet::decode(&packet.encode()).expect("decodes"), packet);
}

#[test]
fn build_keeps_a_learned_route_at_the_width_it_was_learned_at() {
    let learned = pack_path_length(2, 3);
    let packet = Packet::build(
        RouteType::Direct,
        PayloadType::TxtMsg,
        learned,
        &[0x01, 0x02, 0x03, 0x04, 0x05, 0x06],
        vec![0xAA],
    );
    assert_eq!(packet.path_length, learned);
    assert_eq!(packet.path_hash_size(), 2);
    assert_eq!(packet.path_hash_count(), 3);
}

// ─── PathBody ──────────────────────────────────────────────────────

/// Two three-byte hops as `Mesh::createPathReturn` lays them out: the packed
/// `path_length`, the path bytes, the extra's type, then the extra.
const FIRMWARE_PATH_RETURN: &[u8] = &[
    0x82, // pack_path_length(3, 2)
    0xA1, 0xA2, 0xA3, 0xB1, 0xB2, 0xB3, // two three-byte hops
    0x03, // PAYLOAD_TYPE_ACK
    0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x07, // six-byte ack hash
];

#[test]
fn a_firmware_path_return_is_understood() {
    let body = PathBody::parse(FIRMWARE_PATH_RETURN).expect("parses");
    assert_eq!(body.path_length, pack_path_length(3, 2));
    assert_eq!(body.path, vec![0xA1, 0xA2, 0xA3, 0xB1, 0xB2, 0xB3]);
    assert_eq!(body.extra_type, Some(PayloadType::Ack as u8));
    assert_eq!(body.extra, vec![0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x07]);
}

#[test]
fn a_path_return_encodes_the_way_the_firmware_reads_it() {
    let body = PathBody {
        path_length: pack_path_length(3, 2),
        path: vec![0xA1, 0xA2, 0xA3, 0xB1, 0xB2, 0xB3],
        extra_type: Some(PayloadType::Ack as u8),
        extra: vec![0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x07],
    };
    assert_eq!(body.encode(), FIRMWARE_PATH_RETURN);
}

/// Six bytes of path written as the byte count `6` would be read by the
/// firmware as six one-byte hops, so the repeaters along the route would match
/// on one byte of a three-byte hash. Guards the defect directly.
#[test]
fn a_path_return_does_not_write_a_byte_count() {
    let body = PathBody {
        path_length: pack_path_length(3, 2),
        path: vec![0xA1, 0xA2, 0xA3, 0xB1, 0xB2, 0xB3],
        extra_type: None,
        extra: Vec::new(),
    };
    assert_eq!(body.encode()[0], 0x82);
    assert_ne!(body.encode()[0], 6);
}

#[test]
fn a_path_return_with_no_bundled_extra_parses() {
    let body = PathBody::parse(&[0x00]).expect("parses");
    assert_eq!(body.path_length, 0);
    assert!(body.path.is_empty());
    assert_eq!(body.extra_type, None);
    assert!(body.extra.is_empty());
}

/// The firmware writes `0xFF` as the dummy type for a return that bundles
/// nothing and masks it to its low nibble on the way in
/// (`MeshCore/src/Mesh.cpp:170`), so it can never be mistaken for an ACK.
#[test]
fn the_extra_type_is_masked_to_its_low_nibble() {
    let mut raw = vec![0x00, 0xFF];
    raw.extend_from_slice(&[0x01, 0x02, 0x03, 0x04]);
    let body = PathBody::parse(&raw).expect("parses");
    assert_eq!(body.extra_type, Some(0x0F));
    assert_ne!(body.extra_type, Some(PayloadType::Ack as u8));
}

#[test]
fn a_path_return_with_an_invalid_path_length_is_rejected() {
    assert!(PathBody::parse(&[]).is_err(), "empty");
    assert!(PathBody::parse(&[0xC1, 0x00]).is_err(), "reserved width");
    assert!(
        PathBody::parse(&[pack_path_length(3, 2), 0xA1, 0xA2]).is_err(),
        "declares six path bytes but supplies two"
    );
}

proptest! {
    /// Anything `path_byte_len` accepts must survive the round trip, and the
    /// leading byte must come back unchanged so the hash width is preserved.
    #[test]
    fn path_bodies_roundtrip(
        hash_size in 1u8..=3,
        hop_count in 0u8..=20,
        extra in prop::collection::vec(any::<u8>(), 0..8),
    ) {
        let path_length = pack_path_length(hash_size, hop_count);
        let byte_len = path_byte_len(path_length).expect("in range");
        let body = PathBody {
            path_length,
            path: (0..byte_len).map(|i| (i as u8) | 0x80).collect(),
            extra_type: Some(PayloadType::Ack as u8),
            extra: extra.iter().map(|b| b | 1).collect(),
        };

        let encoded = body.encode();
        prop_assert_eq!(encoded[0], path_length);
        let parsed = PathBody::parse(&encoded).expect("parses");
        prop_assert_eq!(parsed.path_length, path_length);
        prop_assert_eq!(&parsed.path, &body.path);
        prop_assert_eq!(path_hash_size(parsed.path_length), hash_size);
        prop_assert_eq!(path_hash_count(parsed.path_length), hop_count);
        prop_assert!(parsed.path.len() <= MAX_PATH_SIZE);
    }
}
