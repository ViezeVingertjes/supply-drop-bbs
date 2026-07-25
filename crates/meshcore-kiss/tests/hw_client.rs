#![allow(missing_docs)]

mod support;

use std::time::Duration;

use meshcore_kiss::hw::client::{HwLink, Unsolicited};
use meshcore_kiss::hw::frame::{HwRequest, HwResponse};
use meshcore_kiss::KissError;
use support::{fake_modem, RECORDED_IDENTITY, RECORDED_SECRET};

const TIMEOUT: Duration = Duration::from_secs(2);

#[tokio::test]
async fn request_returns_the_matching_response() {
    let (stream, _modem) = fake_modem();
    let mut link = HwLink::new(stream, TIMEOUT);

    match link.request(HwRequest::GetIdentity).await.expect("request") {
        HwResponse::Identity { pubkey } => assert_eq!(pubkey, RECORDED_IDENTITY),
        other => panic!("unexpected {other:?}"),
    }
}

#[tokio::test]
async fn consecutive_requests_do_not_cross_responses() {
    let (stream, _modem) = fake_modem();
    let mut link = HwLink::new(stream, TIMEOUT);

    assert!(matches!(
        link.request(HwRequest::Ping).await.expect("ping"),
        HwResponse::Pong
    ));
    assert!(matches!(
        link.request(HwRequest::GetIdentity)
            .await
            .expect("identity"),
        HwResponse::Identity { .. }
    ));
    assert!(matches!(
        link.request(HwRequest::GetRadio).await.expect("radio"),
        HwResponse::Radio(_)
    ));
    match link
        .request(HwRequest::KeyExchange {
            peer_pubkey: [0x5C; 32],
        })
        .await
        .expect("key exchange")
    {
        HwResponse::SharedSecret { secret } => assert_eq!(secret, RECORDED_SECRET),
        other => panic!("unexpected {other:?}"),
    }
}

#[tokio::test]
async fn device_error_is_returned_rather_than_awaited() {
    let (stream, _modem) = fake_modem();
    let mut link = HwLink::new(stream, TIMEOUT);
    modem_rejects_unknown_sub(&mut link).await;
}

async fn modem_rejects_unknown_sub<S>(link: &mut HwLink<S>)
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send,
{
    let response = link
        .request(HwRequest::GetRandom { len: 0 })
        .await
        .expect("request completes");
    assert!(matches!(response, HwResponse::Random { .. }));
}

#[tokio::test]
async fn decrypt_mac_failure_surfaces_as_a_device_error() {
    let (stream, modem) = fake_modem();
    modem.set_decrypt_fails(true);
    let mut link = HwLink::new(stream, TIMEOUT);

    let response = link
        .request(HwRequest::DecryptData {
            key: RECORDED_SECRET,
            mac: [0x00, 0x00],
            ciphertext: vec![0xAA; 16],
        })
        .await
        .expect("request completes");

    match response {
        HwResponse::Error(err) => assert_eq!(err, meshcore_kiss::HwError::MacFailed),
        other => panic!("unexpected {other:?}"),
    }
}

#[tokio::test]
async fn inbound_packets_arriving_mid_request_are_queued_not_matched() {
    let (stream, modem) = fake_modem();
    modem.deliver(&[0x11, 0x22, 0x33], 20, -60);
    let mut link = HwLink::new(stream, TIMEOUT);

    assert!(matches!(
        link.request(HwRequest::Ping).await.expect("ping"),
        HwResponse::Pong
    ));
    link.pump(Duration::from_millis(200)).await.expect("pump");

    let events = drain(&mut link);
    let packets: Vec<Vec<u8>> = events
        .iter()
        .filter_map(|event| match event {
            Unsolicited::Packet { bytes } => Some(bytes.clone()),
            _ => None,
        })
        .collect();
    assert_eq!(packets, vec![vec![0x11, 0x22, 0x33]]);

    let meta = events
        .iter()
        .find(|event| matches!(event, Unsolicited::RxMeta { .. }))
        .expect("rx meta accompanies the packet");
    match meta {
        Unsolicited::RxMeta { snr_db, rssi_dbm } => {
            assert!((snr_db - 5.0).abs() < f32::EPSILON);
            assert_eq!(*rssi_dbm, -60);
        }
        other => panic!("unexpected {other:?}"),
    }
}

#[tokio::test]
async fn send_data_transmits_the_packet_and_reports_tx_done() {
    let (stream, modem) = fake_modem();
    let mut link = HwLink::new(stream, TIMEOUT);

    link.send_data(&[0xAA, 0xBB]).await.expect("send");
    link.pump(Duration::from_millis(200)).await.expect("pump");

    assert_eq!(modem.transmitted(), vec![vec![0xAA, 0xBB]]);
    assert!(drain(&mut link)
        .iter()
        .any(|event| matches!(event, Unsolicited::TxDone { success: true })));
}

#[tokio::test]
async fn tx_busy_is_reported_as_a_device_error_event() {
    let (stream, modem) = fake_modem();
    modem.set_tx_busy_once(true);
    let mut link = HwLink::new(stream, TIMEOUT);

    link.send_data(&[0xAA]).await.expect("send");
    link.pump(Duration::from_millis(200)).await.expect("pump");

    assert!(modem.transmitted().is_empty());
    assert!(drain(&mut link)
        .iter()
        .any(|event| matches!(event, Unsolicited::Error(meshcore_kiss::HwError::TxBusy))));
}

#[tokio::test]
async fn request_times_out_when_the_device_never_answers() {
    let (stream, modem) = fake_modem();
    modem.silence_sub(0x17);
    let mut link = HwLink::new(stream, Duration::from_millis(150));

    let err = link
        .request(HwRequest::Ping)
        .await
        .expect_err("should time out");
    match err {
        KissError::Timeout { sub } => assert_eq!(sub, 0x17),
        other => panic!("unexpected {other:?}"),
    }
}

#[tokio::test]
async fn link_recovers_after_a_timed_out_request() {
    let (stream, modem) = fake_modem();
    modem.silence_sub(0x17);
    let mut link = HwLink::new(stream, Duration::from_millis(150));

    assert!(link.request(HwRequest::Ping).await.is_err());
    match link.request(HwRequest::GetIdentity).await.expect("request") {
        HwResponse::Identity { pubkey } => assert_eq!(pubkey, RECORDED_IDENTITY),
        other => panic!("unexpected {other:?}"),
    }
}

#[tokio::test]
async fn unsolicited_traffic_is_kept_in_arrival_order() {
    let (stream, modem) = fake_modem();
    modem.deliver(&[0x01], 4, -50);
    modem.deliver(&[0x02], 8, -55);
    let mut link = HwLink::new(stream, TIMEOUT);

    link.pump(Duration::from_millis(200)).await.expect("pump");

    let packets: Vec<Vec<u8>> = drain(&mut link)
        .into_iter()
        .filter_map(|event| match event {
            Unsolicited::Packet { bytes } => Some(bytes),
            _ => None,
        })
        .collect();
    assert_eq!(packets, vec![vec![0x01], vec![0x02]]);
}

fn drain<S>(link: &mut HwLink<S>) -> Vec<Unsolicited>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send,
{
    std::iter::from_fn(|| link.next_unsolicited()).collect()
}
