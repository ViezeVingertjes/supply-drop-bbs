#![allow(missing_docs)]

use std::time::Duration;

use meshcore_kiss::hw::client::HwLink;
use meshcore_kiss::hw::frame::{HwRequest, HwResponse};
use meshcore_kiss::HwError;
use tokio_serial::SerialPortBuilderExt;

const TIMEOUT: Duration = Duration::from_secs(2);

fn port() -> Option<String> {
    match std::env::var("SDBBS_KISS_PORT") {
        Ok(value) if !value.is_empty() => Some(value),
        _ => {
            eprintln!("skipping: set SDBBS_KISS_PORT to a KISS modem device to run this test");
            None
        }
    }
}

async fn open(port: &str) -> HwLink<tokio_serial::SerialStream> {
    let stream = tokio_serial::new(port, 115_200)
        .open_native_async()
        .expect("opens the serial port");
    let mut link = HwLink::new(stream, TIMEOUT);
    tokio::time::sleep(Duration::from_millis(250)).await;
    let _ = link.request(HwRequest::Ping).await;
    link
}

#[tokio::test]
#[cfg_attr(
    not(feature = "hardware-tests"),
    ignore = "needs --features hardware-tests"
)]
async fn device_answers_every_query_we_depend_on() {
    let Some(port) = port() else { return };
    let mut link = open(&port).await;

    assert!(matches!(
        link.request(HwRequest::Ping).await.expect("ping"),
        HwResponse::Pong
    ));

    let identity = match link
        .request(HwRequest::GetIdentity)
        .await
        .expect("identity")
    {
        HwResponse::Identity { pubkey } => pubkey,
        other => panic!("unexpected {other:?}"),
    };
    assert_ne!(identity, [0u8; 32]);
    assert_ne!(identity[0], 0x00);
    assert_ne!(identity[0], 0xFF);

    match link.request(HwRequest::GetRadio).await.expect("radio") {
        HwResponse::Radio(params) => {
            assert!(params.frequency_hz > 100_000_000);
            assert!(params.bandwidth_hz >= 7_800);
            assert!((5..=12).contains(&params.spreading_factor));
            assert!((5..=8).contains(&params.coding_rate));
        }
        other => panic!("unexpected {other:?}"),
    }

    match link.request(HwRequest::GetTxPower).await.expect("tx power") {
        HwResponse::TxPower { dbm } => assert!(dbm <= 30),
        other => panic!("unexpected {other:?}"),
    }

    match link
        .request(HwRequest::GetDeviceName)
        .await
        .expect("device name")
    {
        HwResponse::DeviceName { name } => assert!(!name.is_empty()),
        other => panic!("unexpected {other:?}"),
    }

    match link.request(HwRequest::GetVersion).await.expect("version") {
        HwResponse::Version { version } => assert!(version >= 1),
        other => panic!("unexpected {other:?}"),
    }
}

#[tokio::test]
#[cfg_attr(
    not(feature = "hardware-tests"),
    ignore = "needs --features hardware-tests"
)]
async fn many_consecutive_requests_never_cross_responses() {
    let Some(port) = port() else { return };
    let mut link = open(&port).await;

    let identity = match link
        .request(HwRequest::GetIdentity)
        .await
        .expect("identity")
    {
        HwResponse::Identity { pubkey } => pubkey,
        other => panic!("unexpected {other:?}"),
    };

    for round in 0..40u32 {
        match link.request(HwRequest::Ping).await.expect("ping") {
            HwResponse::Pong => {}
            other => panic!("round {round} got {other:?}"),
        }
        match link
            .request(HwRequest::GetIdentity)
            .await
            .expect("identity")
        {
            HwResponse::Identity { pubkey } => assert_eq!(pubkey, identity, "round {round}"),
            other => panic!("round {round} got {other:?}"),
        }
        match link
            .request(HwRequest::Hash {
                data: round.to_le_bytes().to_vec(),
            })
            .await
            .expect("hash")
        {
            HwResponse::Hash { .. } => {}
            other => panic!("round {round} got {other:?}"),
        }
    }
}

#[tokio::test]
#[cfg_attr(
    not(feature = "hardware-tests"),
    ignore = "needs --features hardware-tests"
)]
async fn encrypt_then_decrypt_roundtrips_and_rejects_tampering() {
    let Some(port) = port() else { return };
    let mut link = open(&port).await;

    let peer = [0x5C; 32];
    let secret = match link
        .request(HwRequest::KeyExchange { peer_pubkey: peer })
        .await
        .expect("key exchange")
    {
        HwResponse::SharedSecret { secret } => secret,
        other => panic!("unexpected {other:?}"),
    };

    let plaintext = b"supply drop kiss roundtrip".to_vec();
    let (mac, ciphertext) = match link
        .request(HwRequest::EncryptData {
            key: secret,
            plaintext: plaintext.clone(),
        })
        .await
        .expect("encrypt")
    {
        HwResponse::Encrypted { mac, ciphertext } => (mac, ciphertext),
        other => panic!("unexpected {other:?}"),
    };
    assert_eq!(ciphertext.len() % 16, 0);

    match link
        .request(HwRequest::DecryptData {
            key: secret,
            mac,
            ciphertext: ciphertext.clone(),
        })
        .await
        .expect("decrypt")
    {
        HwResponse::Decrypted { plaintext: out } => {
            assert_eq!(&out[..plaintext.len()], &plaintext[..]);
        }
        other => panic!("unexpected {other:?}"),
    }

    let mut tampered = ciphertext;
    tampered[0] ^= 0xFF;
    match link
        .request(HwRequest::DecryptData {
            key: secret,
            mac,
            ciphertext: tampered,
        })
        .await
        .expect("decrypt completes")
    {
        HwResponse::Error(err) => assert_eq!(err, HwError::MacFailed),
        other => panic!("tampered ciphertext should fail the mac, got {other:?}"),
    }
}

#[tokio::test]
#[cfg_attr(
    not(feature = "hardware-tests"),
    ignore = "needs --features hardware-tests"
)]
async fn sign_then_verify_roundtrips_and_rejects_altered_data() {
    let Some(port) = port() else { return };
    let mut link = open(&port).await;

    let identity = match link
        .request(HwRequest::GetIdentity)
        .await
        .expect("identity")
    {
        HwResponse::Identity { pubkey } => pubkey,
        other => panic!("unexpected {other:?}"),
    };

    let data = b"advert signing vector".to_vec();
    let signature = match link
        .request(HwRequest::SignData { data: data.clone() })
        .await
        .expect("sign")
    {
        HwResponse::Signature { signature } => signature,
        other => panic!("unexpected {other:?}"),
    };

    match link
        .request(HwRequest::VerifySignature {
            pubkey: identity,
            signature,
            data: data.clone(),
        })
        .await
        .expect("verify")
    {
        HwResponse::Verify { valid } => assert!(valid),
        other => panic!("unexpected {other:?}"),
    }

    let mut altered = data;
    altered.push(0x21);
    match link
        .request(HwRequest::VerifySignature {
            pubkey: identity,
            signature,
            data: altered,
        })
        .await
        .expect("verify")
    {
        HwResponse::Verify { valid } => assert!(!valid),
        other => panic!("unexpected {other:?}"),
    }
}

#[tokio::test]
#[cfg_attr(
    not(feature = "hardware-tests"),
    ignore = "needs --features hardware-tests"
)]
async fn client_handshake_synthesises_self_info() {
    use meshcore_companion::client::ClientEvent;
    use meshcore_kiss::client::{KissClient, KissClientConfig};

    let Some(port) = port() else { return };
    let mut config = KissClientConfig::new(port);
    config.node_name = "Supply Drop Test".into();
    let mut client = KissClient::connect(config);

    let event = tokio::time::timeout(Duration::from_secs(10), client.recv())
        .await
        .expect("handshake completes within 10s")
        .expect("an event arrives");

    let ClientEvent::Connected { self_info } = event else {
        panic!("expected Connected, got {event:?}");
    };
    let info = self_info.expect("the kiss backend always synthesises SelfInfo");

    assert_eq!(info.adv_type, 1);
    assert_eq!(info.node_name, "Supply Drop Test");
    assert_ne!(info.pubkey, [0u8; 32]);
    assert!(info.frequency_khz > 100_000);
    assert!((5..=12).contains(&info.spreading_factor));
    assert!((5..=8).contains(&info.coding_rate));
    assert!(info.bandwidth_hz >= 7_800);
}

#[tokio::test]
#[cfg_attr(
    not(feature = "hardware-tests"),
    ignore = "needs --features hardware-tests"
)]
async fn flood_scope_key_and_transport_code_match_the_firmware() {
    use meshcore_kiss::node::scope::FloodScope;
    use meshcore_kiss::packet::PayloadType;

    let Some(port) = port() else { return };
    let mut link = open(&port).await;

    let scope = FloodScope::derive(&mut link, "nl")
        .await
        .expect("derives the scope key");
    assert_eq!(
        scope.key(),
        [
            0xa8, 0x28, 0x9f, 0x73, 0x66, 0x5c, 0x28, 0x05, 0x7d, 0x4f, 0x38, 0x15, 0xa6, 0x00,
            0x29, 0x21,
        ],
        "SHA256(\"#nl\") truncated to sixteen bytes"
    );

    let code = scope
        .transport_code(&mut link, PayloadType::Advert, &[0xAA, 0xBB, 0xCC])
        .await
        .expect("computes the transport code");
    assert_eq!(code, 0x6E97);

    let same = scope
        .transport_code(&mut link, PayloadType::Advert, &[0xAA, 0xBB, 0xCC])
        .await
        .expect("computes the transport code");
    assert_eq!(code, same, "the code must be deterministic");

    let other_payload = scope
        .transport_code(&mut link, PayloadType::Advert, &[0xAA, 0xBB, 0xCD])
        .await
        .expect("computes the transport code");
    assert_ne!(code, other_payload, "the payload must feed the code");

    let other_type = scope
        .transport_code(&mut link, PayloadType::TxtMsg, &[0xAA, 0xBB, 0xCC])
        .await
        .expect("computes the transport code");
    assert_ne!(code, other_type, "the payload type must feed the code");
}
