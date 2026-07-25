#![allow(missing_docs)]

use meshcore_kiss::kiss::{encode, Decoder, FEND, FESC, TFEND, TFESC};
use proptest::prelude::*;

#[test]
fn encode_wraps_payload_in_fend_delimiters() {
    assert_eq!(encode(0x06, &[0x17]), vec![FEND, 0x06, 0x17, FEND]);
}

#[test]
fn encode_escapes_fend_and_fesc_in_payload() {
    assert_eq!(
        encode(0x00, &[FEND, 0x01, FESC]),
        vec![FEND, 0x00, FESC, TFEND, 0x01, FESC, TFESC, FEND]
    );
}

#[test]
fn encode_escapes_a_type_byte_that_collides_with_a_delimiter() {
    assert_eq!(encode(FESC, &[0x01]), vec![FEND, FESC, TFESC, 0x01, FEND]);
}

#[test]
fn decoder_recovers_escaped_payload() {
    let mut decoder = Decoder::new();
    decoder.push(&encode(0x00, &[FEND, 0x01, FESC]));
    let frame = decoder.next_frame().expect("one frame");
    assert_eq!(frame.type_byte, 0x00);
    assert_eq!(frame.data, vec![FEND, 0x01, FESC]);
    assert!(decoder.next_frame().is_none());
}

#[test]
fn decoder_handles_frames_split_across_reads() {
    let bytes = encode(0x06, &[0x81, 0xAA, 0xBB]);
    let mut decoder = Decoder::new();
    decoder.push(&bytes[..3]);
    assert!(decoder.next_frame().is_none());
    decoder.push(&bytes[3..]);
    let frame = decoder.next_frame().expect("one frame");
    assert_eq!(frame.data, vec![0x81, 0xAA, 0xBB]);
}

#[test]
fn decoder_handles_a_split_landing_between_fesc_and_its_escapee() {
    let bytes = encode(0x00, &[FEND]);
    let split = bytes.len() - 2;
    let mut decoder = Decoder::new();
    decoder.push(&bytes[..split]);
    decoder.push(&bytes[split..]);
    let frame = decoder.next_frame().expect("one frame");
    assert_eq!(frame.data, vec![FEND]);
}

#[test]
fn decoder_yields_multiple_frames_from_one_read() {
    let mut bytes = encode(0x06, &[0x97]);
    bytes.extend_from_slice(&encode(0x00, &[0x01, 0x02]));
    let mut decoder = Decoder::new();
    decoder.push(&bytes);
    assert_eq!(decoder.next_frame().expect("first").data, vec![0x97]);
    assert_eq!(decoder.next_frame().expect("second").data, vec![0x01, 0x02]);
    assert!(decoder.next_frame().is_none());
}

#[test]
fn decoder_skips_empty_frames_from_back_to_back_delimiters() {
    let mut decoder = Decoder::new();
    decoder.push(&[FEND, FEND, FEND, 0x06, 0x97, FEND]);
    let frame = decoder.next_frame().expect("one frame");
    assert_eq!(frame.type_byte, 0x06);
    assert_eq!(frame.data, vec![0x97]);
    assert!(decoder.next_frame().is_none());
}

#[test]
fn decoder_ignores_bytes_before_the_first_delimiter() {
    let mut decoder = Decoder::new();
    decoder.push(&[0xDE, 0xAD, 0xBE, 0xEF]);
    decoder.push(&encode(0x06, &[0x97]));
    let frame = decoder.next_frame().expect("one frame");
    assert_eq!(frame.data, vec![0x97]);
}

#[test]
fn decoder_drops_oversized_frames_without_stalling() {
    let mut decoder = Decoder::new();
    decoder.push(&encode(0x00, &vec![0xAB; 600]));
    decoder.push(&encode(0x06, &[0x97]));
    let frame = decoder
        .next_frame()
        .expect("recovers after an oversized frame");
    assert_eq!(frame.data, vec![0x97]);
    assert!(decoder.next_frame().is_none());
}

#[test]
fn decoder_accepts_a_frame_at_exactly_the_size_limit() {
    let body = vec![0xAB; meshcore_kiss::kiss::MAX_KISS_FRAME - 1];
    let mut decoder = Decoder::new();
    decoder.push(&encode(0x00, &body));
    let frame = decoder.next_frame().expect("one frame");
    assert_eq!(frame.data.len(), body.len());
}

#[test]
fn type_byte_splits_into_port_and_command() {
    let mut decoder = Decoder::new();
    decoder.push(&encode(0x36, &[0x00]));
    let frame = decoder.next_frame().expect("one frame");
    assert_eq!(frame.port(), 0x03);
    assert_eq!(frame.command(), 0x06);
}

#[test]
fn has_frames_tracks_the_ready_queue() {
    let mut decoder = Decoder::new();
    assert!(!decoder.has_frames());
    decoder.push(&encode(0x06, &[0x97]));
    assert!(decoder.has_frames());
    decoder.next_frame();
    assert!(!decoder.has_frames());
}

proptest! {
    #[test]
    fn encode_decode_roundtrips(
        type_byte in any::<u8>(),
        data in prop::collection::vec(any::<u8>(), 0..400),
    ) {
        let mut decoder = Decoder::new();
        decoder.push(&encode(type_byte, &data));
        let frame = decoder.next_frame().expect("roundtrip frame");
        prop_assert_eq!(frame.type_byte, type_byte);
        prop_assert_eq!(frame.data, data);
    }

    #[test]
    fn roundtrip_survives_arbitrary_chunk_boundaries(
        data in prop::collection::vec(any::<u8>(), 1..200),
        split in 1usize..64,
    ) {
        let bytes = encode(0x00, &data);
        let mut decoder = Decoder::new();
        for chunk in bytes.chunks(split) {
            decoder.push(chunk);
        }
        let frame = decoder.next_frame().expect("roundtrip frame");
        prop_assert_eq!(frame.data, data);
    }
}
