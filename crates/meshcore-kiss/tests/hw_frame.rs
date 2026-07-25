#![allow(missing_docs)]

use meshcore_kiss::error::HwError;
use meshcore_kiss::hw::frame::{
    DeviceStats, HwRequest, HwResponse, RadioParams, CMD_DATA, CMD_SET_HARDWARE, RESP_ERROR,
    RESP_OK, RESP_RX_META, RESP_TX_DONE, SUB_GET_AIRTIME, SUB_GET_BATTERY, SUB_GET_DEVICE_NAME,
    SUB_GET_IDENTITY, SUB_GET_RADIO, SUB_GET_RANDOM, SUB_GET_STATS, SUB_GET_TX_POWER,
    SUB_GET_VERSION, SUB_PING,
};
use proptest::prelude::*;

#[test]
fn ping_encodes_to_sub_command_only() {
    assert_eq!(HwRequest::Ping.encode(), vec![0x17]);
    assert_eq!(HwRequest::Ping.expected_response(), 0x97);
}

#[test]
fn key_exchange_encodes_pubkey_after_sub_command() {
    let peer = [0xAB; 32];
    let encoded = HwRequest::KeyExchange { peer_pubkey: peer }.encode();
    assert_eq!(encoded[0], 0x07);
    assert_eq!(&encoded[1..], &peer[..]);
    assert_eq!(
        HwRequest::KeyExchange { peer_pubkey: peer }.expected_response(),
        0x87
    );
}

#[test]
fn set_radio_encodes_little_endian_hz_then_sf_cr() {
    let encoded = HwRequest::SetRadio(RadioParams {
        frequency_hz: 869_618_000,
        bandwidth_hz: 62_500,
        spreading_factor: 7,
        coding_rate: 5,
    })
    .encode();
    assert_eq!(encoded[0], 0x09);
    assert_eq!(&encoded[1..5], &869_618_000u32.to_le_bytes());
    assert_eq!(&encoded[5..9], &62_500u32.to_le_bytes());
    assert_eq!(encoded[9], 7);
    assert_eq!(encoded[10], 5);
}

#[test]
fn decode_identity_response() {
    let mut body = vec![0x81];
    body.extend_from_slice(&[0x42; 32]);
    match HwResponse::decode(&body).expect("decodes") {
        HwResponse::Identity { pubkey } => assert_eq!(pubkey, [0x42; 32]),
        other => panic!("unexpected {other:?}"),
    }
}

#[test]
fn decode_radio_response_matches_probe_capture() {
    let body = vec![
        0x8B, 0x50, 0x51, 0xD5, 0x33, 0x24, 0xF4, 0x00, 0x00, 0x07, 0x05,
    ];
    match HwResponse::decode(&body).expect("decodes") {
        HwResponse::Radio(params) => {
            assert_eq!(params.frequency_hz, 869_618_000);
            assert_eq!(params.bandwidth_hz, 62_500);
            assert_eq!(params.spreading_factor, 7);
            assert_eq!(params.coding_rate, 5);
        }
        other => panic!("unexpected {other:?}"),
    }
}

#[test]
fn decode_error_response_maps_mac_failed() {
    match HwResponse::decode(&[0xF1, 0x04]).expect("decodes") {
        HwResponse::Error(err) => assert_eq!(err, HwError::MacFailed),
        other => panic!("unexpected {other:?}"),
    }
}

#[test]
fn decode_encrypted_splits_mac_from_ciphertext() {
    let body = vec![0x85, 0x5B, 0x6A, 0x77, 0x33, 0x2D, 0x8C];
    match HwResponse::decode(&body).expect("decodes") {
        HwResponse::Encrypted { mac, ciphertext } => {
            assert_eq!(mac, [0x5B, 0x6A]);
            assert_eq!(ciphertext, vec![0x77, 0x33, 0x2D, 0x8C]);
        }
        other => panic!("unexpected {other:?}"),
    }
}

#[test]
fn decode_rx_meta_reports_quarter_db_snr() {
    match HwResponse::decode(&[0xF9, 0x14, 0xC4]).expect("decodes") {
        HwResponse::RxMeta { snr_db, rssi_dbm } => {
            assert!((snr_db - 5.0).abs() < f32::EPSILON);
            assert_eq!(rssi_dbm, -60);
        }
        other => panic!("unexpected {other:?}"),
    }
}

#[test]
fn decode_tx_done_reports_success_flag() {
    match HwResponse::decode(&[0xF8, 0x01]).expect("decodes") {
        HwResponse::TxDone { success } => assert!(success),
        other => panic!("unexpected {other:?}"),
    }
}

#[test]
fn decode_device_name_is_utf8() {
    let mut body = vec![0x96];
    body.extend_from_slice(b"Xiao S3 WIO");
    match HwResponse::decode(&body).expect("decodes") {
        HwResponse::DeviceName { name } => assert_eq!(name, "Xiao S3 WIO"),
        other => panic!("unexpected {other:?}"),
    }
}

#[test]
fn decode_truncated_body_is_malformed() {
    assert!(HwResponse::decode(&[0x8B, 0x01]).is_err());
    assert!(HwResponse::decode(&[]).is_err());
}

#[test]
fn kiss_command_numbers_match_the_protocol() {
    assert_eq!(CMD_DATA, 0x00);
    assert_eq!(CMD_SET_HARDWARE, 0x06);
    assert_eq!(RESP_OK, 0xF0);
    assert_eq!(RESP_ERROR, 0xF1);
    assert_eq!(RESP_TX_DONE, 0xF8);
    assert_eq!(RESP_RX_META, 0xF9);
}

#[test]
fn bodyless_requests_encode_to_a_single_sub_command_byte() {
    let cases = [
        (HwRequest::GetIdentity, SUB_GET_IDENTITY),
        (HwRequest::GetRadio, SUB_GET_RADIO),
        (HwRequest::GetTxPower, SUB_GET_TX_POWER),
        (HwRequest::GetVersion, SUB_GET_VERSION),
        (HwRequest::GetStats, SUB_GET_STATS),
        (HwRequest::GetBattery, SUB_GET_BATTERY),
        (HwRequest::GetDeviceName, SUB_GET_DEVICE_NAME),
        (HwRequest::Ping, SUB_PING),
    ];
    for (request, sub) in cases {
        assert_eq!(request.sub(), sub, "sub for {request:?}");
        assert_eq!(request.encode(), vec![sub], "encoding of {request:?}");
        assert_eq!(
            request.expected_response(),
            sub | 0x80,
            "expected response for {request:?}"
        );
    }
}

#[test]
fn single_byte_requests_encode_their_argument() {
    assert_eq!(HwRequest::GetRandom { len: 32 }.encode(), vec![0x02, 32]);
    assert_eq!(
        HwRequest::GetRandom { len: 32 }.expected_response(),
        SUB_GET_RANDOM | 0x80
    );
    assert_eq!(HwRequest::SetTxPower { dbm: 22 }.encode(), vec![0x0A, 22]);
    assert_eq!(
        HwRequest::GetAirtime { packet_len: 64 }.encode(),
        vec![0x0F, 64]
    );
    assert_eq!(
        HwRequest::GetAirtime { packet_len: 64 }.expected_response(),
        SUB_GET_AIRTIME | 0x80
    );
}

#[test]
fn radio_setters_expect_the_generic_ok_response() {
    let params = RadioParams {
        frequency_hz: 869_618_000,
        bandwidth_hz: 62_500,
        spreading_factor: 7,
        coding_rate: 5,
    };
    assert_eq!(HwRequest::SetRadio(params).expected_response(), RESP_OK);
    assert_eq!(
        HwRequest::SetTxPower { dbm: 22 }.expected_response(),
        RESP_OK
    );
}

#[test]
fn sign_and_hash_encode_the_bare_payload() {
    let data = vec![0x01, 0x02, 0x03];
    assert_eq!(
        HwRequest::SignData { data: data.clone() }.encode(),
        vec![0x04, 0x01, 0x02, 0x03]
    );
    assert_eq!(
        HwRequest::Hash { data: data.clone() }.encode(),
        vec![0x08, 0x01, 0x02, 0x03]
    );
    assert_eq!(HwRequest::SignData { data }.expected_response(), 0x84);
}

#[test]
fn verify_signature_encodes_pubkey_then_signature_then_data() {
    let pubkey = [0x11; 32];
    let signature = [0x22; 64];
    let encoded = HwRequest::VerifySignature {
        pubkey,
        signature,
        data: vec![0x33, 0x44],
    }
    .encode();
    assert_eq!(encoded.len(), 1 + 32 + 64 + 2);
    assert_eq!(encoded[0], 0x03);
    assert_eq!(&encoded[1..33], &pubkey[..]);
    assert_eq!(&encoded[33..97], &signature[..]);
    assert_eq!(&encoded[97..], &[0x33, 0x44]);
}

#[test]
fn encrypt_data_encodes_key_then_plaintext() {
    let key = [0x55; 32];
    let encoded = HwRequest::EncryptData {
        key,
        plaintext: vec![0x66, 0x77],
    }
    .encode();
    assert_eq!(encoded.len(), 1 + 32 + 2);
    assert_eq!(encoded[0], 0x05);
    assert_eq!(&encoded[1..33], &key[..]);
    assert_eq!(&encoded[33..], &[0x66, 0x77]);
}

#[test]
fn decrypt_data_encodes_key_then_mac_then_ciphertext() {
    let key = [0x55; 32];
    let encoded = HwRequest::DecryptData {
        key,
        mac: [0x5B, 0x6A],
        ciphertext: vec![0x77, 0x33],
    }
    .encode();
    assert_eq!(encoded.len(), 1 + 32 + 2 + 2);
    assert_eq!(encoded[0], 0x06);
    assert_eq!(&encoded[1..33], &key[..]);
    assert_eq!(&encoded[33..35], &[0x5B, 0x6A]);
    assert_eq!(&encoded[35..], &[0x77, 0x33]);
    assert_eq!(
        HwRequest::DecryptData {
            key,
            mac: [0x5B, 0x6A],
            ciphertext: vec![0x77, 0x33],
        }
        .expected_response(),
        0x86
    );
}

#[test]
fn decode_shared_secret_matches_probe_capture() {
    let body = vec![
        0x87, 0xF4, 0xD3, 0x34, 0x57, 0x82, 0x27, 0x1B, 0xD9, 0x0F, 0xA1, 0x8B, 0x5F, 0x1B, 0xF8,
        0x67, 0xEB, 0x3C, 0x2E, 0x77, 0x01, 0x91, 0xF0, 0x61, 0x7A, 0x32, 0x6B, 0xA8, 0xFD, 0xAA,
        0x05, 0x34, 0x77,
    ];
    match HwResponse::decode(&body).expect("decodes") {
        HwResponse::SharedSecret { secret } => {
            assert_eq!(secret[0], 0xF4);
            assert_eq!(secret[31], 0x77);
        }
        other => panic!("unexpected {other:?}"),
    }
}

#[test]
fn decode_version_response_matches_probe_capture() {
    match HwResponse::decode(&[0x91, 0x01, 0x00]).expect("decodes") {
        HwResponse::Version { version } => assert_eq!(version, 1),
        other => panic!("unexpected {other:?}"),
    }
}

#[test]
fn decode_stats_response_reads_three_distinct_counters() {
    let mut body = vec![0x92];
    body.extend_from_slice(&7u32.to_le_bytes());
    body.extend_from_slice(&300u32.to_le_bytes());
    body.extend_from_slice(&66_000u32.to_le_bytes());
    match HwResponse::decode(&body).expect("decodes") {
        HwResponse::Stats(stats) => assert_eq!(
            stats,
            DeviceStats {
                rx: 7,
                tx: 300,
                errors: 66_000,
            }
        ),
        other => panic!("unexpected {other:?}"),
    }
}

#[test]
fn decode_zeroed_stats_capture() {
    let body = vec![0x92, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    match HwResponse::decode(&body).expect("decodes") {
        HwResponse::Stats(stats) => assert_eq!(
            stats,
            DeviceStats {
                rx: 0,
                tx: 0,
                errors: 0,
            }
        ),
        other => panic!("unexpected {other:?}"),
    }
}

#[test]
fn decode_battery_response_is_little_endian_millivolts() {
    match HwResponse::decode(&[0x93, 0xA0, 0x0F]).expect("decodes") {
        HwResponse::Battery { millivolts } => assert_eq!(millivolts, 4000),
        other => panic!("unexpected {other:?}"),
    }
    match HwResponse::decode(&[0x93, 0x00, 0x00]).expect("decodes") {
        HwResponse::Battery { millivolts } => assert_eq!(millivolts, 0),
        other => panic!("unexpected {other:?}"),
    }
}

#[test]
fn decode_airtime_response_is_little_endian_millis() {
    match HwResponse::decode(&[0x8F, 0x2C, 0x01, 0x00, 0x00]).expect("decodes") {
        HwResponse::Airtime { millis } => assert_eq!(millis, 300),
        other => panic!("unexpected {other:?}"),
    }
}

#[test]
fn decode_tx_power_response_matches_probe_capture() {
    match HwResponse::decode(&[0x8C, 0x16]).expect("decodes") {
        HwResponse::TxPower { dbm } => assert_eq!(dbm, 22),
        other => panic!("unexpected {other:?}"),
    }
}

#[test]
fn decode_bodyless_responses() {
    assert_eq!(
        HwResponse::decode(&[0x97]).expect("decodes"),
        HwResponse::Pong
    );
    assert_eq!(
        HwResponse::decode(&[0xF0]).expect("decodes"),
        HwResponse::Ok
    );
}

#[test]
fn decode_verify_response_reports_validity() {
    match HwResponse::decode(&[0x83, 0x01]).expect("decodes") {
        HwResponse::Verify { valid } => assert!(valid),
        other => panic!("unexpected {other:?}"),
    }
    match HwResponse::decode(&[0x83, 0x00]).expect("decodes") {
        HwResponse::Verify { valid } => assert!(!valid),
        other => panic!("unexpected {other:?}"),
    }
}

#[test]
fn decode_signature_response_is_sixty_four_bytes() {
    let mut body = vec![0x84];
    body.extend_from_slice(&[0x9C; 64]);
    match HwResponse::decode(&body).expect("decodes") {
        HwResponse::Signature { signature } => assert_eq!(signature, [0x9C; 64]),
        other => panic!("unexpected {other:?}"),
    }
}

#[test]
fn decode_hash_response_is_thirty_two_bytes() {
    let mut body = vec![0x88];
    body.extend_from_slice(&[0x3D; 32]);
    match HwResponse::decode(&body).expect("decodes") {
        HwResponse::Hash { digest } => assert_eq!(digest, [0x3D; 32]),
        other => panic!("unexpected {other:?}"),
    }
}

#[test]
fn decode_variable_tails_accept_any_remainder() {
    match HwResponse::decode(&[0x82, 0x01, 0x02]).expect("decodes") {
        HwResponse::Random { bytes } => assert_eq!(bytes, vec![0x01, 0x02]),
        other => panic!("unexpected {other:?}"),
    }
    match HwResponse::decode(&[0x86]).expect("decodes") {
        HwResponse::Decrypted { plaintext } => assert!(plaintext.is_empty()),
        other => panic!("unexpected {other:?}"),
    }
    match HwResponse::decode(&[0x96]).expect("decodes") {
        HwResponse::DeviceName { name } => assert!(name.is_empty()),
        other => panic!("unexpected {other:?}"),
    }
    match HwResponse::decode(&[0x85, 0x5B, 0x6A]).expect("decodes") {
        HwResponse::Encrypted { mac, ciphertext } => {
            assert_eq!(mac, [0x5B, 0x6A]);
            assert!(ciphertext.is_empty());
        }
        other => panic!("unexpected {other:?}"),
    }
}

#[test]
fn decode_rx_meta_handles_negative_snr() {
    match HwResponse::decode(&[0xF9, 0xF4, 0x92]).expect("decodes") {
        HwResponse::RxMeta { snr_db, rssi_dbm } => {
            assert!((snr_db + 3.0).abs() < f32::EPSILON);
            assert_eq!(rssi_dbm, -110);
        }
        other => panic!("unexpected {other:?}"),
    }
}

#[test]
fn decode_tx_done_reports_failure() {
    match HwResponse::decode(&[0xF8, 0x00]).expect("decodes") {
        HwResponse::TxDone { success } => assert!(!success),
        other => panic!("unexpected {other:?}"),
    }
}

#[test]
fn decode_error_response_preserves_unrecognised_codes() {
    match HwResponse::decode(&[0xF1, 0x07]).expect("decodes") {
        HwResponse::Error(err) => assert_eq!(err, HwError::TxBusy),
        other => panic!("unexpected {other:?}"),
    }
    match HwResponse::decode(&[0xF1, 0x7F]).expect("decodes") {
        HwResponse::Error(err) => assert_eq!(err, HwError::Other(0x7F)),
        other => panic!("unexpected {other:?}"),
    }
}

#[test]
fn decode_unmodelled_response_code_is_preserved_verbatim() {
    match HwResponse::decode(&[0x8D, 0xC4]).expect("decodes") {
        HwResponse::Unknown { code, body } => {
            assert_eq!(code, 0x8D);
            assert_eq!(body, vec![0xC4]);
        }
        other => panic!("unexpected {other:?}"),
    }
}

#[test]
fn decode_device_name_rejects_invalid_utf8() {
    assert!(HwResponse::decode(&[0x96, 0xFF, 0xFE]).is_err());
}

#[test]
fn decode_short_fixed_layout_bodies_are_malformed() {
    let mut short_identity = vec![0x81];
    short_identity.extend_from_slice(&[0x00; 31]);
    let mut short_signature = vec![0x84];
    short_signature.extend_from_slice(&[0x00; 63]);
    let mut short_secret = vec![0x87];
    short_secret.extend_from_slice(&[0x00; 31]);
    let mut short_hash = vec![0x88];
    short_hash.extend_from_slice(&[0x00; 31]);
    let mut short_stats = vec![0x92];
    short_stats.extend_from_slice(&[0x00; 11]);

    let cases: Vec<Vec<u8>> = vec![
        short_identity,
        vec![0x83],
        short_signature,
        vec![0x85, 0x5B],
        short_secret,
        short_hash,
        vec![0x8B, 0x01],
        vec![0x8C],
        vec![0x8F, 0x00, 0x00, 0x00],
        vec![0x91, 0x01],
        short_stats,
        vec![0x93, 0x00],
        vec![0xF1],
        vec![0xF8],
        vec![0xF9, 0x14],
    ];
    for body in cases {
        assert!(
            HwResponse::decode(&body).is_err(),
            "expected a malformed error for {body:02X?}"
        );
    }
}

proptest! {
    #[test]
    fn radio_params_survive_an_encode_decode_round_trip(
        frequency_hz in any::<u32>(),
        bandwidth_hz in any::<u32>(),
        spreading_factor in any::<u8>(),
        coding_rate in any::<u8>(),
    ) {
        let params = RadioParams {
            frequency_hz,
            bandwidth_hz,
            spreading_factor,
            coding_rate,
        };
        let mut body = HwRequest::SetRadio(params).encode();
        body[0] = 0x8B;
        prop_assert_eq!(
            HwResponse::decode(&body).expect("decodes"),
            HwResponse::Radio(params)
        );
    }

    #[test]
    fn encrypted_bodies_split_at_the_mac_for_any_ciphertext(
        mac in any::<[u8; 2]>(),
        ciphertext in proptest::collection::vec(any::<u8>(), 0..64),
    ) {
        let mut body = vec![0x85];
        body.extend_from_slice(&mac);
        body.extend_from_slice(&ciphertext);
        prop_assert_eq!(
            HwResponse::decode(&body).expect("decodes"),
            HwResponse::Encrypted { mac, ciphertext }
        );
    }

    #[test]
    fn any_response_code_decodes_or_errors_without_panicking(
        body in proptest::collection::vec(any::<u8>(), 0..80),
    ) {
        let _ = HwResponse::decode(&body);
    }
}
